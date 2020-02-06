from pathlib import Path

import click
from cryptography.hazmat.backends import default_backend
from cryptography import x509
from cryptography.hazmat.primitives.serialization import load_pem_private_key

from cert_tool_cluster import CertToolCluster
from certtool_sddc import CertToolSddc
from certtool_vc import CertToolVc
from esxi_cert_tool.utils_certs import get_msca_root_cert


@click.group()
def generate():
    pass


@generate.command('ca')
@click.option('--ca_crt', type=click.Path(exists=False), default='ca.crt', help=f'Output file for the CA certificate')
@click.option('--ca_key', type=click.Path(exists=False), default='ca.key', help=f'Output file for the CA key')
@click.option('--organization', type=str, default='VMware Inc.', help=f'Certificate Organization')
@click.option('--unit', type=str, default='HCIBU', help=f'Certificate Unit')
@click.option('--locality', type=str, default='Palo Alto', help=f'Certificate Locality')
@click.option('--state', type=str, default='California', help=f'Certificate State or Province')
@click.option('--country', type=str, default='US', help=f'Certificate Country')
@click.option('--validity', type=click.IntRange(min=1, clamp=True), default=365, help=f'Number of days valid')
@click.option('--key-length', type=int, default=4096, help=f'Private key size')
@click.option('--verbose', is_flag=True, help=f'Print lots of output')
@click.pass_context
def generate_ca(ctx, ca_crt: str,  ca_key: str, organization: str, unit: str, locality: str, state: str, country: str, validity: int, key_length: int, verbose: bool):

    if verbose or True:
        print(f'Generating a new CA certificate and key\n'
              f' Certificate: {ca_crt}\n'
              f' Key        : {ca_key}\n'
              f' Validity   : {validity}\n'
              f' Key length : {key_length}\n'
              f' C          : {country}\n'
              f' ST         : {state}\n'
              f' L          : {locality}\n'
              f' O          : {organization}\n'
              f' U          : {unit}')

    """Create a CA certificate and key"""
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    import datetime
    import uuid

    today = datetime.datetime.today()
    one_day = datetime.timedelta(days=1)
    one_year = datetime.timedelta(days=validity)
    ca_cn = f'CA-{uuid.uuid1()}'

    # Generate private key
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_length, backend=default_backend())

    # Generate public key
    public_key = private_key.public_key()
    builder = x509.CertificateBuilder()
    builder = builder.subject_name(x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, ca_cn),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, unit),
        x509.NameAttribute(NameOID.LOCALITY_NAME, locality),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, state),
        x509.NameAttribute(NameOID.COUNTRY_NAME, country),
    ]))

    builder = builder.issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, ca_cn)]))
    builder = builder.not_valid_before(today - one_day)
    builder = builder.not_valid_after(today + one_year)
    builder = builder.serial_number(x509.random_serial_number())
    builder = builder.public_key(public_key)
    builder = builder.add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
    certificate = builder.sign(private_key=private_key, algorithm=hashes.SHA256(), backend=default_backend())

    with Path(ca_key) as file:
        ca_key_bytes = private_key.private_bytes(encoding=serialization.Encoding.PEM,
                                                 format=serialization.PrivateFormat.PKCS8,
                                                 encryption_algorithm=serialization.NoEncryption())
        file.write_bytes(ca_key_bytes)

    with Path(ca_crt) as file:
        ca_crt_bytes = certificate.public_bytes(encoding=serialization.Encoding.PEM)
        file.write_bytes(ca_crt_bytes)

    print(f'CA certificate and key successfully generated')
