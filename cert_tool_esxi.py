import progressbar
import uuid

from certsrv import Certsrv
from contextlib import contextmanager
from datetime import datetime
from fabric import Connection, Result
from OpenSSL.crypto import load_certificate, FILETYPE_PEM
from pathlib import Path
from pyVmomi import vim
from time import sleep
from typing import List

from utils import create_cert_config, ping, create_openssl_config, host_down, host_up, get_msca_root_cert
from vc_cluster import VcCluster


class CertToolEsx(object):

    def __init__(self,
                 vc_server: str,
                 vc_user: str,
                 vc_pass: str,
                 vc_datacenter: str,
                 vc_cluster: str,
                 vc_ssh_user: str,
                 vc_ssh_pass: str,
                 esx_user: str,
                 esx_pass: str,
                 verbose: bool = False):

        # Parameters
        self.esx_crt = '/etc/vmware/ssl/rui.crt'
        self.esx_key = '/etc/vmware/ssl/rui.key'

        # vCenter
        self.vc_server = vc_server
        self.vc_user = vc_user
        self.vc_pass = vc_pass
        self.vc_datacenter = vc_datacenter
        self.vc_cluster = vc_cluster

        self.vc_ssh_user = vc_ssh_user
        self.vc_ssh_pass = vc_ssh_pass

        self.esx_user = esx_user
        self.esx_pass = esx_pass

        self.verbose = verbose

        # Create vCenter API connection
        self.vcc = VcCluster(hostname=vc_server,
                             username=vc_user,
                             password=vc_pass,
                             datacenter=vc_datacenter,
                             cluster=vc_cluster)

        # Create vCenter SSH connection
        self.vc_ssh = Connection(host=vc_server, user=vc_ssh_user, connect_kwargs={"password": vc_ssh_pass})

        self.cert_dir = Path(f'./certs')
        if not self.cert_dir.exists():
            self.cert_dir.mkdir()

        # File names
        self.cert_cfg_file = 'rui.cfg'
        self.cert_key_file = 'rui.key'
        self.cert_csr_file = 'rui.csr'
        self.cert_crt_file = 'rui.crt'
        self.cert_chain_file = 'rui-chain.crt'
        self.ca_cfg_file = 'ca.cfg'
        self.ca_crt_file = 'ca.crt'
        self.ca_key_file = 'ca.key'

        # Remote temporary folder
        self.remote_folder = Path('/tmp')

        # Remote temporary files
        self.remote_cfg = str(self.remote_folder / self.cert_cfg_file)
        self.remote_csr = str(self.remote_folder / self.cert_csr_file)
        self.remote_crt = str(self.remote_folder / self.cert_crt_file)
        self.remote_chain = str(self.remote_folder / self.cert_chain_file)
        self.remote_key = str(self.remote_folder / self.cert_key_file)
        self.remote_ca_cfg = str(self.remote_folder / self.ca_cfg_file)
        self.remote_ca_crt = str(self.remote_folder / self.ca_crt_file)
        self.remote_ca_key = str(self.remote_folder / self.ca_key_file)

    def __del__(self):
        if self.vc_ssh:
            self.vc_ssh.close()

    @staticmethod
    @contextmanager
    def __maintenance_mode(vcc: VcCluster, host: vim.HostSystem, timeout: int = 900):
        try:
            if host.runtime.connectionState == vim.HostSystem.ConnectionState.connected:
                task = host.EnterMaintenanceMode_Task(timeout)
                vcc.wait_for_tasks([task])
            yield
        finally:
            if host.runtime.connectionState == vim.HostSystem.ConnectionState.connected:
                task = host.ExitMaintenanceMode_Task(timeout)
                vcc.wait_for_tasks([task])

    @staticmethod
    @contextmanager
    def __disconnected(vcc: VcCluster, host: vim.HostSystem):

        try:
            if host.runtime.connectionState == vim.HostSystem.ConnectionState.connected:
                task = host.DisconnectHost_Task()
                vcc.wait_for_tasks([task])
            yield

        finally:
            if host.runtime.connectionState != vim.HostSystem.ConnectionState.connected:
                task = host.ReconnectHost_Task()
                vcc.wait_for_tasks([task])

    def __vc_run(self, cmd: str) -> Result:
        result = self.vc_ssh.run(f"shell {cmd}", pty=True, hide=True)
        result.stdout = result.stdout.split('\r\n', 1)[1]
        sleep(3)
        return result

    def install_self_signed_to_esxi(self):

        date = datetime.now().strftime('%Y%m%d%H%M%S')
        cert_dir = self.cert_dir / self.vcc.cluster.name / date

        if not cert_dir.exists():
            cert_dir.mkdir(parents=True)

        local_ca_cfg: Path = cert_dir / self.ca_cfg_file
        local_ca_crt: Path = cert_dir / self.ca_crt_file
        local_ca_key: Path = cert_dir / self.ca_key_file

        # Get hosts in cluster
        hosts = sorted(self.vcc.hosts, key=lambda x: x.name)
        if len(hosts) < 1:
            raise RuntimeError(f'There are no hosts in cluster: {self.vcc.cluster.name}')

        # Check hosts
        errors: List[str] = []
        for host in hosts:
            if host.runtime.connectionState != vim.HostSystem.ConnectionState.connected:
                errors.append(f'{host.name} not connected')
                continue
            if host.runtime.inMaintenanceMode:
                errors.append(f'{host.name} in maintenance mode')
                continue
        if errors:
            raise RuntimeError(f'Hosts are not in ready state: {", ".join([msg for msg in errors])}')

        # 1. Generate CA certificate on first host

        # 1.1. Create ESXi host connection
        hostname = hosts[0].name
        host_connection = Connection(host=hostname, user=self.esx_user, connect_kwargs={"password": self.esx_pass})

        # 1.2. Create openssl config
        cn = f'CA-{uuid.uuid1()}'
        config = create_openssl_config(host=hostname, cn=cn)
        if self.verbose:
            print(f'ca.cfg:\n{config}')
        local_ca_cfg.write_text(config)
        host_connection.put(local=local_ca_cfg, remote=self.remote_ca_cfg)

        # 1.3. Create CA crt and key
        cmd = f'openssl req ' \
              f'-x509 ' \
              f'-newkey rsa:4096 ' \
              f'-keyout {self.remote_ca_key} ' \
              f'-out {self.remote_ca_crt} ' \
              f'-days 365 ' \
              f'-nodes ' \
              f'-config {self.remote_ca_cfg}'
        if self.verbose:
            print(f'cmd: {cmd}')
        result = host_connection.run(f'{cmd}', pty=True, hide=True)
        host_connection.get(local=local_ca_key, remote=self.remote_ca_key)
        host_connection.get(local=local_ca_crt, remote=self.remote_ca_crt)

        # 1.4. Copy CA crt to VC
        cmd = f'sshpass -p "{self.esx_pass}" ' \
              f'scp -q ' \
              f'-o StrictHostKeyChecking=no ' \
              f'-o UserKnownHostsFile=/dev/null {self.esx_user}@{hostname}:{self.remote_ca_crt} {self.remote_ca_crt}'
        if self.verbose:
            print(f'cmd: {cmd}')
        result = self.__vc_run(cmd)

        # 1.5. Add CA crt to VC trusted certs
        cmd = f'/usr/lib/vmware-vmafd/bin/dir-cli trustedcert publish ' \
              f'--cert {self.remote_ca_crt} ' \
              f'--login {self.vc_user} ' \
              f'--password {self.vc_pass}'
        if self.verbose:
            print(f'cmd: {cmd}')
        result = self.__vc_run(cmd)

        # 1.6. Refresh certs across SSO
        cmd = f'/usr/lib/vmware-vmafd/bin/vecs-cli force-refresh'
        if self.verbose:
            print(f'cmd: {cmd}')
        result = self.__vc_run(cmd)

        # 2. Generate a new certificate for each hosts
        for host in hosts:

            hostname = host.name
            host_dir = cert_dir / hostname
            print(f'Replacing the certificate on {hostname}')

            if not host_dir.exists():
                host_dir.mkdir()

            local_cfg: Path = host_dir / self.cert_cfg_file
            local_csr: Path = host_dir / self.cert_csr_file
            local_key: Path = host_dir / self.cert_key_file
            local_crt: Path = host_dir / self.cert_crt_file
            local_chain: Path = host_dir / self.cert_chain_file

            # 2.1. Create ESXi host connection
            host_connection = Connection(host=hostname, user=self.esx_user, connect_kwargs={"password": self.esx_pass})

            # 2.2. Copy CA cfg, crt and key over to host
            host_connection.put(local=local_ca_cfg, remote=self.remote_ca_cfg)
            host_connection.put(local=local_ca_key, remote=self.remote_ca_key)
            host_connection.put(local=local_ca_crt, remote=self.remote_ca_crt)

            # 2.3. Create certificate configuration
            config = create_cert_config(host=hostname)
            if self.verbose:
                print(f'rui.cfg:\n{config}')
            local_cfg.write_text(config)
            host_connection.put(local=local_cfg, remote=self.remote_cfg)

            # 2.3. Create certificate request
            cmd = f'openssl req ' \
                  f'-new -nodes ' \
                  f'-out {self.remote_csr} ' \
                  f'-keyout {self.remote_key} ' \
                  f'-config {self.remote_cfg}'
            if self.verbose:
                print(f'cmd: {cmd}')
            result = host_connection.run(f"{cmd}", pty=True, hide=True)
            host_connection.get(local=local_csr, remote=self.remote_csr)
            host_connection.get(local=local_key, remote=self.remote_key)

            # 2.4. Sign CSR with root CA
            cmd = f'openssl x509 ' \
                  f'-req ' \
                  f'-days 360 ' \
                  f'-in {self.remote_csr} ' \
                  f'-CA {self.remote_ca_crt} ' \
                  f'-CAkey {self.remote_ca_key} ' \
                  f'-CAcreateserial ' \
                  f'-out {self.remote_crt} ' \
                  f'-extfile {self.remote_ca_cfg} ' \
                  f'-extensions v3_req'
            if self.verbose:
                print(f'cmd: {cmd}')
            result = host_connection.run(f'{cmd}', pty=True, hide=True)
            host_connection.get(local=local_crt, remote=self.remote_crt)

            # 2.6. Create certificate chain
            cmd = f'cat {self.remote_crt} {self.remote_ca_crt} > {self.remote_chain}'
            if self.verbose:
                print(f'cmd: {cmd}')
            result = host_connection.run(f'{cmd}', pty=True, hide=True)
            host_connection.get(local=local_chain, remote=self.remote_chain)

            # 2.7. Set host in maintenance mode
            with self.__maintenance_mode(vcc=self.vcc, host=host), self.__disconnected(vcc=self.vcc, host=host):

                esx_crt_bak = host_dir / f'rui.crt.bak'
                esx_key_bak = host_dir / f'rui.key.bak'

                # 2.7.1 Backup certs
                host_connection.get(local=esx_crt_bak, remote=self.esx_crt)
                host_connection.get(local=esx_key_bak, remote=self.esx_key)

                # 2.7.2 Copy new cert
                host_connection.put(local=local_chain, remote=self.esx_crt)
                host_connection.put(local=local_key, remote=self.esx_key)

                # 2.7.3 Reboot host
                cmd = f'esxcli system shutdown reboot --delay=10 --reason="installing new certs"'
                if self.verbose:
                    print(f'cmd: {cmd}')
                result = host_connection.run(f"{cmd}", pty=True, hide=True)

                # Wait for reboot to complete
                # Tried just restarting the management agents hostd and vpxa, but the host would
                # not reconnect correctly.
                print(f'Waiting for host {hostname} to shutdown')
                host_down(hostname=hostname)

                # Wait for host to respond
                print(f'Waiting for host {hostname} to power up')
                host_up(hostname=hostname)

                # Make for services to start up
                print(f'Waiting for services to start')
                sleep(120)

                # Try to reconnect host
                print(f'Trying to reconnect host {hostname}...')
                retries = 30
                with progressbar.ProgressBar(max_value=retries) as bar:
                    for i in range(retries):
                        bar.update(i)
                        sleep(30)
                        try:
                            spec = vim.HostConnectSpec(userName=self.esx_user, password=self.esx_pass)
                            task = host.ReconnectHost_Task(cnxSpec=spec)
                            self.vcc.wait_for_tasks([task])
                            break
                        except vim.fault.NoHost:
                            pass
                        if i + 1 > retries:
                            raise RuntimeError(f'Host failed to reconnect after {retries} tries')

            print(f'Complete')

    def install_msca_cert_to_esxi(self, ca_server: str, ca_user: str, ca_pass: str):

        date = datetime.now().strftime('%Y%m%d%H%M%S')
        host_dir = self.cert_dir / self.vcc.cluster.name / date

        if not host_dir.exists():
            host_dir.mkdir(parents=True)

        local_ca_crt: Path = host_dir / self.ca_crt_file

        # Get hosts in cluster
        hosts = sorted(self.vcc.hosts, key=lambda x: x.name)
        if len(hosts) < 1:
            raise RuntimeError(f'There are no hosts in cluster: {self.vcc.cluster.name}')

        # Check hosts
        errors: List[str] = []
        for host in hosts:
            if host.runtime.connectionState != vim.HostSystem.ConnectionState.connected:
                errors.append(f'{host.name} not connected')
                continue
            if host.runtime.inMaintenanceMode:
                errors.append(f'{host.name} in maintenance mode')
                continue
        if errors:
            raise RuntimeError(f'Hosts are not in ready state: {", ".join([msg for msg in errors])}')

        # 1. Get the Microsoft Certificate Authority file
        ca_crt_str = get_msca_root_cert(hostname=ca_server, username=ca_user, password=ca_pass)
        local_ca_crt.write_text(ca_crt_str)

        # Connect to Microsoft Certificate Authority
        cert_srv = Certsrv(server=ca_server, username=ca_user, password=ca_pass, cafile=str(local_ca_crt))
        cert_srv.check_credentials()

        # Process hosts
        for host in hosts:

            hostname = host.name
            host_dir = self.cert_dir / hostname

            if not host_dir.exists():
                host_dir.mkdir()

            local_cfg: Path = host_dir / self.cert_cfg_file
            local_csr: Path = host_dir / self.cert_csr_file
            local_key: Path = host_dir / self.cert_key_file
            local_crt: Path = host_dir / self.cert_crt_file

            print(f'Replacing the certificate on {hostname}')

            # Create ESXi host connection
            host_connection = Connection(host=hostname, user=self.esx_user, connect_kwargs={"password": self.esx_pass})

            # Create certificate configuration
            config = create_cert_config(host=host.name)
            local_cfg.write_text(config)
            host_connection.put(local=local_cfg, remote=self.remote_cfg)

            # Create certificate request
            cmd = f'openssl req -new -nodes -out {self.remote_csr} -keyout {self.remote_key} -config {self.remote_cfg}'
            result = host_connection.run(f"{cmd}", pty=True, hide=True)

            # Get certificate request and key
            host_connection.get(local=local_csr, remote=self.remote_csr)
            host_connection.get(local=local_key, remote=self.remote_key)

            # Load signing request
            data = local_csr.read_bytes()

            # Get signed certificate
            ms_cert_bytes = cert_srv.get_cert(data, "WebServer")
            ms_cert = load_certificate(FILETYPE_PEM, ms_cert_bytes)
            local_crt.write_bytes(ms_cert_bytes)
            host_connection.put(local=local_crt, remote=self.remote_crt)

            # Set host in maintenance mode
            with self.__maintenance_mode(vcc=self.vcc, host=host), self.__disconnected(vcc=self.vcc, host=host):

                esx_crt_bak = host_dir / f'rui.crt.{date}'
                esx_key_bak = host_dir / f'rui.key.{date}'

                # Backup certs
                host_connection.get(local=esx_crt_bak, remote=self.esx_crt)
                host_connection.get(local=esx_key_bak, remote=self.esx_key)

                # Copy new cert
                host_connection.put(local=local_crt, remote=self.esx_crt)
                host_connection.put(local=local_key, remote=self.esx_key)

                # Reboot host
                cmd = f'esxcli system shutdown reboot --delay=10 --reason="installing new certs"'
                result = host_connection.run(f"{cmd}", pty=True, hide=True)

                # Wait for reboot to complete
                # Tried just restarting the management agents hostd and vpxa, but the host would
                # not reconnect correctly.
                print(f'Waiting for host {hostname} to shutdown')
                host_down(hostname=hostname)

                # Wait for host to respond
                print(f'Waiting for host {hostname} to power up')
                host_up(hostname=hostname)

                # Make for services to start up
                print(f'Waiting for services to start')
                sleep(120)

                # Try to reconnect host
                print(f'Trying to reconnect host {hostname}...')
                retries = 120
                with progressbar.ProgressBar(max_value=retries) as bar:
                    for i in range(retries):
                        bar.update(i)
                        sleep(10)
                        try:
                            spec = vim.HostConnectSpec(userName=self.esx_user, password=self.esx_pass)
                            task = host.ReconnectHost_Task(cnxSpec=spec)
                            self.vcc.wait_for_tasks([task])
                            break
                        except vim.fault.NoHost:
                            pass
                        if i+1 > retries:
                            raise RuntimeError(f'Host failed to reconnect after {retries} tries')

            print(f'Host {hostname} complete')

        print(f'Replacement complete')
