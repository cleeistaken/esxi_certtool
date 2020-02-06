import progressbar
import pysftp
import re
import tempfile
import uuid

from contextlib import contextmanager
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from fabric import Connection, Result
from time import sleep
from typing import Dict
from pathlib import Path


class CertToolVc(object):

    def __init__(self,
                 vc_server: str,
                 vc_user: str,
                 vc_pass: str,
                 vc_ssh_user: str,
                 vc_ssh_pass: str,
                 verbose: bool = False):
        # Variables
        self.vc_server = vc_server
        self.vc_user = vc_user
        self.vc_pass = vc_pass
        self.vc_ssh_user = vc_ssh_user
        self.vc_ssh_pass = vc_ssh_pass
        self.verbose = verbose

        # Create vCenter SSH connection
        self.vc_ssh = Connection(host=self.vc_server,
                                 user=self.vc_ssh_user,
                                 connect_kwargs={"password": self.vc_ssh_pass})

        # Parameters
        self.dir_cli = '/usr/lib/vmware-vmafd/bin/dir-cli'
        self.vecs_cli = '/usr/lib/vmware-vmafd/bin/vecs-cli'

    def __del__(self):
        if self.vc_ssh:
            self.vc_ssh.close()

    def __vc_run(self, cmd: str, shell: bool = True) -> Result:
        prefix = 'shell ' if shell else ''
        result = self.vc_ssh.run(f"{prefix}{cmd}", pty=True, hide=True)
        result.stdout = result.stdout.split('\r\n', 1)[1]
        sleep(3)
        return result

    @contextmanager
    def __bash_shell(self):
        try:
            cmd = f'chsh -s /bin/bash {self.vc_ssh_user}'
            result = self.__vc_run(cmd)
            yield

        finally:
            cmd = f'chsh -s /bin/appliancesh {self.vc_ssh_user}'
            result = self.__vc_run(cmd)

    def get_certs(self) -> Dict:

        re_cn = re.compile(r'CN\(id\):\s+(.{40})\r')
        re_crt = re.compile(r'-{5}BEGIN CERTIFICATE-{5}[\s\S.]+-{5}END CERTIFICATE-{5}')

        # Get VC certificates list
        cmd = f'{self.dir_cli} trustedcert list --login {self.vc_user} --password {self.vc_pass}'
        result = self.__vc_run(cmd)
        cert_list = result.stdout

        # Find number of certs
        re_nb_certs = re.compile(r'Number of certificates:	(\d+)\r')
        match = re_nb_certs.search(cert_list)
        if match:
            nb_certs = int(match.group(1))
        else:
            nb_certs = 0

        # Find aliases
        cns = re_cn.findall(cert_list, re.MULTILINE)

        # Get certificates
        certs = {}

        with progressbar.ProgressBar(max_value=len(cns)) as bar:
            for i, cn in enumerate(cns):
                bar.update(i)
                cmd = f'{self.dir_cli} trustedcert get ' \
                      f'--login {self.vc_user} ' \
                      f'--password {self.vc_pass} ' \
                      f'--id {cn} ' \
                      f'--outcert /dev/stdout'
                result = self.__vc_run(cmd)
                match = re_crt.search(result.stdout)
                cert_bytes = match.group(0).encode('utf-8')
                certs[cn] = x509.load_pem_x509_certificate(cert_bytes, default_backend())

        return certs

    def add_cert(self, ca_crt: x509):

        # Get current certs
        certs = self.get_certs()

        # Check if requested ca_cert is already installed
        for cid, cert in certs.items():
            if cert.public_bytes(serialization.Encoding.PEM) == ca_crt.public_bytes(serialization.Encoding.PEM):
                print(f'Cert is already in VC trusted CA certificates as id {cid}')
                return

        # Create temporary file
        ca_crt_file = tempfile.NamedTemporaryFile(delete=False)
        ca_crt_bytes = ca_crt.public_bytes(encoding=serialization.Encoding.PEM)
        ca_crt_file.write(ca_crt_bytes)
        ca_crt_file.close()
        ca_crt_filename = ca_crt_file.name

        try:

            # Upload certificate tp
            remote_tmp = f'/tmp/ca-cert-{uuid.uuid1()}'
            with self.__bash_shell():
                with pysftp.Connection(self.vc_server, username=self.vc_ssh_user, password=self.vc_ssh_pass) as sftp:
                    sftp.put(ca_crt_filename, remote_tmp)

            # Add CA certificate to VC trusted certs
            cmd = f'{self.dir_cli} trustedcert publish ' \
                  f'--cert {remote_tmp} ' \
                  f'--login {self.vc_user} ' \
                  f'--password {self.vc_pass}'
            if self.verbose:
                print(f'cmd: {cmd}')
            result = self.__vc_run(cmd)

            # Refresh SSO certificate store
            cmd = f'{self.vecs_cli} force-refresh'
            if self.verbose:
                print(f'cmd: {cmd}')
            result = self.__vc_run(cmd)

            # Delete remote temporary file
            cmd = f'rm {remote_tmp}'
            if self.verbose:
                print(f'cmd: {cmd}')
            result = self.__vc_run(cmd)

        finally:

            # Delete local temporary file
            Path(ca_crt_filename).unlink()
