from contextlib import contextmanager
from cryptography import x509
from datetime import datetime
from fabric import Connection, Result
from pathlib import Path
from pyVmomi import vim
from time import sleep
from typing import List

from esxi_cert_tool.cert_tool_esxi import CertToolEsxi
from esxi_cert_tool.vc_cluster import VcCluster


class CertToolCluster(object):

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
        self.ca_crt_file = '../ca.crt'
        self.ca_key_file = '../ca.key'

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

    @staticmethod
    def __check_hosts(hosts: List[vim.HostSystem]) -> List[str]:
        errors: List[str] = []
        for host in hosts:
            if host.runtime.connectionState != vim.HostSystem.ConnectionState.connected:
                errors.append(f'{host.name} not connected')
                continue
            if host.runtime.inMaintenanceMode:
                errors.append(f'{host.name} in maintenance mode')
                continue
        return errors

    def __vc_run(self, cmd: str) -> Result:
        result = self.vc_ssh.run(f"shell {cmd}", pty=True, hide=True)
        result.stdout = result.stdout.split('\r\n', 1)[1]
        sleep(3)
        return result

    def install_self_signed_to_esxi(self, ca_crt: x509, ca_key: x509):

        # Create folder
        date = datetime.now().strftime('%Y%m%d%H%M%S')
        cluster_name = self.vcc.cluster.name
        cluster_dir = self.cert_dir / cluster_name / date
        if not cluster_dir.exists():
            cluster_dir.mkdir(parents=True)

        # Get hosts in cluster
        hosts = sorted(self.vcc.hosts, key=lambda x: x.name)
        if len(hosts) < 1:
            raise RuntimeError(f'There are no hosts in cluster: {self.vcc.cluster.name}')

        # Check hosts
        errors = self.__check_hosts(hosts)
        if errors:
            raise RuntimeError(f'Hosts are not in ready state: {", ".join([msg for msg in errors])}')

        # Generate a new certificate for each hosts
        for host in hosts:

            # Set host in maintenance mode and disconnect
            with self.__maintenance_mode(vcc=self.vcc, host=host), self.__disconnected(vcc=self.vcc, host=host):

                # Deploying new crt and key
                print(f'Generating new certificate and key for host {host.name}')
                cte = CertToolEsxi(esx_server=host.name,
                                   esx_user=self.esx_user,
                                   esx_pass=self.esx_pass,
                                   output_folder=cluster_dir,
                                   verbose=self.verbose)
                cte.install_selfsigned(ca_crt=ca_crt, ca_key=ca_key)

                print(f'Host {host.name} complete')

        print(f'Cluster {cluster_name} host certificate replacement complete')

    def install_msca_cert_to_esxi(self, ca_server: str, ca_user: str, ca_pass: str):

        # Create folder
        date = datetime.now().strftime('%Y%m%d%H%M%S')
        cluster_name = self.vcc.cluster.name
        cluster_dir = self.cert_dir / cluster_name / date
        if not cluster_dir.exists():
            cluster_dir.mkdir(parents=True)

        # Get hosts in cluster
        hosts = sorted(self.vcc.hosts, key=lambda x: x.name)
        if len(hosts) < 1:
            raise RuntimeError(f'There are no hosts in cluster: {self.vcc.cluster.name}')

        # Check hosts
        errors = self.__check_hosts(hosts)
        if errors:
            raise RuntimeError(f'Hosts are not in ready state: {", ".join([msg for msg in errors])}')

        # Process hosts
        for host in hosts:

            # Set host in maintenance mode and disconnect from VC
            with self.__maintenance_mode(vcc=self.vcc, host=host), self.__disconnected(vcc=self.vcc, host=host):

                print(f'Deploying new certificate on host {host.name} using Microsoft CA {ca_server}')
                cte = CertToolEsxi(esx_server=host.name,
                                   esx_user=self.esx_user,
                                   esx_pass=self.esx_pass,
                                   output_folder=cluster_dir,
                                   verbose=self.verbose)
                cte.install_msca_signed(ca_server=ca_server, ca_user=ca_user, ca_pass=ca_pass)

            print(f'Host {host.name} complete')

        print(f'Cluster {cluster_name} host certificate replacement complete')
