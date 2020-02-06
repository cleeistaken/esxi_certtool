import uuid
from datetime import datetime, timedelta

from enum import Enum
from pathlib import Path
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography import x509

from cert_tool_cluster import CertToolCluster
from esxi_cert_tool.cli.commands import cli


class CertOperation(Enum):
    self_signed = 1
    msca = 2


def main():

    '''csr_bytes = Path('./certs/cluster02/20200128201001/test01esx05.lab02.vsanpe.vmware.com/rui.csr').read_bytes()
    csr = x509.load_pem_x509_csr(csr_bytes, default_backend())
    foo = csr.public_bytes(encoding=serialization.Encoding.PEM)

    ocrt_bytes = Path('./certs/cluster02/20200128201001/ca.crt').read_bytes()
    ocrt = x509.load_pem_x509_certificate(ocrt_bytes, default_backend())
    ofoo = ocrt.public_bytes(encoding=serialization.Encoding.PEM)

    crt_bytes = Path('./certs/cluster02/20200128201001/ca.crt').read_bytes()
    crt = x509.load_pem_x509_certificate(crt_bytes, default_backend())
    foo = crt.public_bytes(encoding=serialization.Encoding.PEM)

    key_bytes = Path('./certs/cluster02/20200128201001/ca.key').read_bytes()
    key = load_pem_private_key(key_bytes, password=None, backend=default_backend())
    bar = key.private_bytes(encoding=serialization.Encoding.PEM,
                            format=serialization.PrivateFormat.PKCS8,
                            encryption_algorithm=serialization.NoEncryption())

    builder = x509.CertificateBuilder()
    builder = builder.subject_name(csr.subject)
    builder = builder.issuer_name(crt.subject)
    builder = builder.public_key(csr.public_key())
    builder = builder.serial_number(int(uuid.uuid4()))
    builder = builder.add_extension(
        x509.BasicConstraints(ca=False, path_length=None), critical=True,
    )
    builder = builder.add_extension(extension=x509.KeyUsage(digital_signature=True,
                                                            key_encipherment=True,
                                                            content_commitment=False,
                                                            data_encipherment=True,
                                                            key_agreement=False,
                                                            encipher_only=False,
                                                            decipher_only=False,
                                                            key_cert_sign=False,
                                                            crl_sign=False), critical=True)
    builder = builder.not_valid_before(datetime.now() - timedelta(days=1))
    builder = builder.not_valid_after(datetime.now() + timedelta(days=363))

    cert = builder.sign(private_key=key, algorithm=hashes.SHA256(), backend=default_backend())'''

    # Call click CLI
    cli()


    """print(f'Connecting to VC: {vc_server} DC: {vc_datacenter} CL: {vc_cluster}')
    cte = CertToolCluster(vc_server=vc_server,
                          vc_user=vc_user,
                          vc_pass=vc_pass,
                          vc_datacenter=vc_datacenter,
                          vc_cluster=vc_cluster,
                          vc_ssh_user=vc_ssh_user,
                          vc_ssh_pass=vc_ssh_pass,
                          esx_user=esx_user,
                          esx_pass=esx_pass,
                          verbose=True)

    if operation == CertOperation.self_signed:
        print(f'Deploying self-signed certificates')
        cte.install_self_signed_to_esxi()

    elif operation == CertOperation.msca:
        print(f'Deploying Microsoft CA certificates')
        cte.install_msca_cert_to_esxi(ca_server=ca_server, ca_user=ca_user, ca_pass=ca_pass)"""


if __name__ == "__main__":
    main()
