from certsrv import Certsrv
from contextlib import contextmanager
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from datetime import datetime
from fabric import Connection
from pathlib import Path
from time import sleep

from esxi_cert_tool.utils import create_cert_config
from esxi_cert_tool.utils_certs import get_msca_root_cert
from esxi_cert_tool.utils_connectivity import host_down, host_up


class CertToolEsxi(object):

    def __init__(self, esx_server: str, esx_user: str, esx_pass: str, output_folder: Path, verbose: bool = False):

        # Parameters
        self.esx_crt = '/etc/vmware/ssl/rui.crt'
        self.esx_key = '/etc/vmware/ssl/rui.key'
        self.remote_tmp = Path('/tmp')
        self.service_start_delay = 120

        # Variables
        self.esx_server = esx_server
        self.esx_user = esx_user
        self.esx_pass = esx_pass
        self.verbose = verbose

        # Create output folder
        self.output_folder = output_folder / self.esx_server
        if not self.output_folder.exists():
            self.output_folder.mkdir(parents=True)

        # Connection
        self.connection = Connection(host=esx_server, user=self.esx_user, connect_kwargs={"password": self.esx_pass})

    @contextmanager
    def __maintenance_mode(self):
        enabled = False
        cmd_get = 'esxcli system maintenanceMode get'
        cmd_enable = 'esxcli system maintenanceMode set --enable True --timeout 600'
        cmd_disable = 'esxcli system maintenanceMode set --enable False --timeout 600'
        try:
            result = self.connection.run(f'{cmd_get}', pty=True, hide=True)
            enabled = 'Enabled' in result.stdout
            if not enabled:
                result = self.connection.run(f'{cmd_enable}', pty=True, hide=True)
            yield
        finally:
            if not enabled:
                result = self.connection.run(f'{cmd_disable}', pty=True, hide=True)

    def __reboot(self):
        with self.__maintenance_mode():
            # Reboot host
            cmd = f'esxcli system shutdown reboot --delay=10 --reason="Installing new SSL certs"'
            result = self.connection.run(f"{cmd}", pty=True, hide=True)

            # Wait for reboot to complete
            print(f'Waiting for host {self.esx_server} to shutdown')
            host_down(hostname=self.esx_server)

            # Wait for host to respond
            print(f'Waiting for host {self.esx_server} to power up')
            host_up(hostname=self.esx_server)

            # Wait for services to start up
            print(f'Waiting {self.service_start_delay} seconds for services to start')
            sleep(self.service_start_delay)

    def install_selfsigned(self, ca_crt: x509, ca_key: x509):

        # Create folder
        date = datetime.now().strftime('%Y%m%d%H%M%S')
        cert_dir = self.output_folder / date
        if not cert_dir.exists():
            cert_dir.mkdir(parents=True)

        # File names
        cert_cfg_file = 'rui.cfg'
        cert_key_file = 'rui.key'
        cert_csr_file = 'rui.csr'
        cert_crt_file = 'rui.crt'
        cert_chain_file = 'rui-chain.crt'
        cert_crt_bak_file = 'rui.crt.bak'
        cert_key_bak_file = 'rui.key.bak'
        ca_crt_file = 'ca.crt'
        ca_key_file = 'ca.key'

        # Create local paths
        local_cfg = cert_dir / cert_cfg_file
        local_csr = cert_dir / cert_csr_file
        local_key = cert_dir / cert_key_file
        local_crt = cert_dir / cert_crt_file
        local_chain = cert_dir / cert_chain_file
        local_crt_bak = cert_dir / cert_crt_bak_file
        local_key_bak = cert_dir / cert_key_bak_file
        local_ca_crt = cert_dir / ca_crt_file
        local_ca_key = cert_dir / ca_key_file

        # Remote temporary files
        remote_cfg = str(self.remote_tmp / cert_cfg_file)
        remote_csr = str(self.remote_tmp / cert_csr_file)
        remote_crt = str(self.remote_tmp / cert_crt_file)
        remote_chain = str(self.remote_tmp / cert_chain_file)
        remote_key = str(self.remote_tmp / cert_key_file)
        remote_ca_crt = str(self.remote_tmp / ca_crt_file)
        remote_ca_key = str(self.remote_tmp / ca_key_file)

        # Write CA crt
        ca_crt_bytes = ca_crt.public_bytes(encoding=serialization.Encoding.PEM)
        local_ca_crt.write_bytes(ca_crt_bytes)
        self.connection.put(local=local_ca_crt, remote=remote_ca_crt)

        # Write CA key
        ca_key_bytes = ca_key.private_bytes(encoding=serialization.Encoding.PEM,
                                            format=serialization.PrivateFormat.PKCS8,
                                            encryption_algorithm=serialization.NoEncryption())
        local_ca_key.write_bytes(ca_key_bytes)
        self.connection.put(local=local_ca_key, remote=remote_ca_key)

        # Create host cfg
        config = create_cert_config(host=self.esx_server)
        local_cfg.write_text(config)
        self.connection.put(local=local_cfg, remote=remote_cfg)

        # Create certificate request
        cmd = f'openssl req ' \
              f'-new -nodes ' \
              f'-out {str(remote_csr)} ' \
              f'-keyout {str(remote_key)} ' \
              f'-config {str(remote_cfg)}'
        result = self.connection.run(f"{cmd}", pty=True, hide=True)
        self.connection.get(local=local_csr, remote=remote_csr)
        self.connection.get(local=local_key, remote=remote_key)

        # Sign CSR with CA key and crt
        cmd = f'openssl x509 ' \
              f'-req ' \
              f'-days 360 ' \
              f'-in {str(remote_csr)} ' \
              f'-CA {str(remote_ca_crt)} ' \
              f'-CAkey {str(remote_ca_key)} ' \
              f'-CAcreateserial ' \
              f'-out {str(remote_crt)} ' \
              f'-extfile {str(remote_cfg)} ' \
              f'-extensions v3_req'
        result = self.connection.run(f'{cmd}', pty=True, hide=True)
        self.connection.get(local=local_crt, remote=remote_crt)

        # Create certificate chain
        cmd = f'cat {str(remote_crt)} {str(remote_ca_crt)} > {str(remote_chain)}'
        result = self.connection.run(f'{cmd}', pty=True, hide=True)
        self.connection.get(local=local_chain, remote=remote_chain)

        # Backup current crt and key
        self.connection.get(local=local_crt_bak, remote=self.esx_crt)
        self.connection.get(local=local_key_bak, remote=self.esx_key)

        # Deploy new crt and key
        self.connection.put(local=local_chain, remote=self.esx_crt)
        self.connection.put(local=local_key, remote=self.esx_key)

        # Reboot host
        self.__reboot()

    def install_msca_signed(self, ca_server: str, ca_user: str, ca_pass: str):

        # Create folder
        date = datetime.now().strftime('%Y%m%d%H%M%S')
        cert_dir = self.output_folder / date
        if not cert_dir.exists():
            cert_dir.mkdir(parents=True)

        # File names
        cert_cfg_file = 'rui.cfg'
        cert_key_file = 'rui.key'
        cert_csr_file = 'rui.csr'
        cert_crt_file = 'rui.crt'
        cert_chain_file = 'rui-chain.crt'
        cert_crt_bak_file = 'rui.crt.bak'
        cert_key_bak_file = 'rui.key.bak'
        ca_crt_file = 'ca.crt'

        # Create local paths
        local_cfg = cert_dir / cert_cfg_file
        local_csr = cert_dir / cert_csr_file
        local_key = cert_dir / cert_key_file
        local_crt = cert_dir / cert_crt_file
        local_chain = cert_dir / cert_chain_file
        local_crt_bak = cert_dir / cert_crt_bak_file
        local_key_bak = cert_dir / cert_key_bak_file
        local_ca_crt = cert_dir / ca_crt_file

        # Remote temporary files
        remote_cfg = str(self.remote_tmp / cert_cfg_file)
        remote_csr = str(self.remote_tmp / cert_csr_file)
        remote_crt = str(self.remote_tmp / cert_crt_file)
        remote_chain = str(self.remote_tmp / cert_chain_file)
        remote_key = str(self.remote_tmp / cert_key_file)
        remote_ca_crt = str( self.remote_tmp / ca_crt_file)

        # Get the Microsoft Certificate Authority file
        ca_crt = get_msca_root_cert(hostname=ca_server, username=ca_user, password=ca_pass)
        local_ca_crt.write_bytes(ca_crt.public_bytes(encoding=serialization.Encoding.PEM))

        # Connect to Microsoft Certificate Authority
        cert_srv = Certsrv(server=ca_server, username=ca_user, password=ca_pass, cafile=str(local_ca_crt))
        cert_srv.check_credentials()
        self.connection.put(local=local_ca_crt, remote=remote_ca_crt)

        # Create host cfg
        config = create_cert_config(host=self.esx_server)
        local_cfg.write_text(config)
        self.connection.put(local=local_cfg, remote=remote_cfg)

        # Create certificate request
        cmd = f'openssl req -new -nodes -out {remote_csr} -keyout {remote_key} -config {remote_cfg}'
        result = self.connection.run(f"{cmd}", pty=True, hide=True)
        self.connection.get(local=local_csr, remote=remote_csr)
        self.connection.get(local=local_key, remote=remote_key)

        # Get signed certificate
        csr_bytes = local_csr.read_bytes()
        crt_bytes = cert_srv.get_cert(csr_bytes, 'WebServer')
        local_crt.write_bytes(crt_bytes)
        self.connection.put(local=local_crt, remote=remote_crt)

        # Create certificate chain
        cmd = f'cat {remote_crt} {remote_ca_crt} > {remote_chain}'
        result = self.connection.run(f'{cmd}', pty=True, hide=True)
        self.connection.get(local=local_chain, remote=remote_chain)

        # Backup current crt and key
        self.connection.get(local=local_crt_bak, remote=self.esx_crt)
        self.connection.get(local=local_key_bak, remote=self.esx_key)

        # Deploy new crt and key
        self.connection.put(local=local_chain, remote=self.esx_crt)
        self.connection.put(local=local_key, remote=self.esx_key)

        # Reboot host
        self.__reboot()
