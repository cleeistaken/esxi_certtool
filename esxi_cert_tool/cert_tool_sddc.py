import re
import tempfile
import uuid
from pathlib import Path

import progressbar
from fabric import Connection, Result
from invoke import Responder
from typing import Dict
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization


class CertToolSddc(object):

    def __init__(self,
                 sddc_server: str,
                 sddc_user: str,
                 sddc_pass: str,
                 verbose: bool = False):

        # Variables
        self.sddc_server = sddc_server
        self.sddc_user = sddc_user
        self.sddc_pass = sddc_pass
        self.verbose = verbose

        # Parameters
        self.java_store = '/etc/alternatives/jre/esxi_cert_tool/security/cacerts'
        self.java_store_password = 'changeit'
        self.common_store = '/etc/vmware/vcf/commonsvcs/trusted_certificates.store'
        self.common_key = '/etc/vmware/vcf/commonsvcs/trusted_certificates.key'

        # Create SDDC manager SSH connection
        self.sddc_ssh = Connection(host=self.sddc_server,
                                   user=self.sddc_user,
                                   connect_kwargs={"password": self.sddc_pass})
        self.sddc_su = Responder(pattern=r'Password:', response=f'{self.sddc_pass}\n')

        #  Get certificate store password
        cmd = f'cat {self.common_key}'
        result = self.__su_cmd(cmd)
        self.common_store_password = result.stdout

    def __su_cmd(self, cmd: str) -> Result:
        result = self.sddc_ssh.run(f"su -c '{cmd}'", pty=True, watchers=[self.sddc_su], hide=True)
        result.stdout = result.stdout.split('\r\n', 1)[1]
        return result

    def __get_certs(self, store: str, password: str) -> Dict:

        # CRT regex
        re_crt = re.compile(r'-{5}BEGIN CERTIFICATE-{5}[\s\S.]+-{5}END CERTIFICATE-{5}')

        # Get certificate list
        cmd = f'keytool -list -v -keystore {store} -storepass {password}'
        result = self.__su_cmd(cmd)
        cert_list = result.stdout

        # Find aliases
        re_alias = re.compile(r'Alias name: (.*)\r')
        aliases = re_alias.findall(cert_list, re.MULTILINE)

        # Get certificates
        certs = {}
        with progressbar.ProgressBar(max_value=len(aliases)) as bar:
            for i, alias in enumerate(aliases):
                bar.update(i)
                cmd = (
                    f'keytool -keystore {store} '
                    f'-exportcert -storepass {password} '
                    f'-alias {alias} | openssl x509 -inform der'
                )
                result = self.__su_cmd(cmd)
                match = re_crt.search(result.stdout)
                crt_bytes = match.group(0).encode('utf-8')
                crt = x509.load_pem_x509_certificate(crt_bytes, default_backend())

                certs[alias] = crt

        return certs

    def __add_cert(self, ca_crt: x509, store: str, password: str, alias: str = None) -> Result:

        if alias is None:
            alias = f'ca-{uuid.uuid1()}'

        # Create temporary file
        ca_crt_file = tempfile.NamedTemporaryFile(delete=False)
        ca_crt_bytes = ca_crt.public_bytes(encoding=serialization.Encoding.PEM)
        ca_crt_file.write(ca_crt_bytes)
        ca_crt_file.close()
        ca_crt_path = Path(ca_crt_file.name)

        try:

            # Upload certificate
            remote_tmp = f'/tmp/ca-cert-{uuid.uuid1()}'
            result = self.sddc_ssh.put(local=ca_crt_path, remote=remote_tmp)

            # Import certificate
            cmd = f'keytool ' \
                  f'-importcert ' \
                  f'-alias {alias} ' \
                  f'-file {remote_tmp} ' \
                  f'-keystore {store} ' \
                  f'-storepass {password} ' \
                  f'-noprompt'
            import_result = self.__su_cmd(cmd)

            # Delete remote temporary file
            cmd = f'rm {remote_tmp}'
            if self.verbose:
                print(f'cmd: {cmd}')
            result = self.__su_cmd(cmd)

        finally:

            # Delete local temporary file
            ca_crt_path.unlink()

        return import_result

    def get_common_certs(self):
        return self.__get_certs(store=self.common_store, password=self.common_store_password)

    def get_java_certs(self) -> Dict:
        return self.__get_certs(store=self.java_store, password=self.java_store_password)

    def add_cert_to_common(self, ca_crt: x509, alias: str = None):

        # Check current certs
        for ca, crt in self.get_common_certs().items():
            if ca_crt.public_bytes(serialization.Encoding.PEM) == crt.public_bytes(serialization.Encoding.PEM):
                print(f'Cert is already in SDDC Common store with alias {ca}')
                return

        return self.__add_cert(ca_crt=ca_crt,
                               store=self.common_store,
                               password=self.common_store_password,
                               alias=alias)

    def add_cert_to_java(self, ca_crt: x509, alias: str = None):

        # Check current certs
        for ca, crt in self.get_java_certs().items():
            if ca_crt.public_bytes == crt.public_bytes:
                print(f'Cert is already in SDDC Java store with alias {ca}')
                return

        return self.__add_cert(ca_crt=ca_crt,
                               store=self.java_store,
                               password=self.java_store_password,
                               alias=alias)

    def add_cert(self, ca_crt: x509, alias: str = None):
        self.add_cert_to_common(ca_crt=ca_crt, alias=alias)
        self.add_cert_to_java(ca_crt=ca_crt, alias=alias)
