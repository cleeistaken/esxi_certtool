import datetime
import socket
import requests
import urllib3
import uuid

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from pathlib import Path


def compare_certs(cert1: x509, cert2: x509) -> bool:
    return cert1.digest("md5") == cert2.digest("md5") \
           and cert1.digest("sha1") == cert2.digest("sha1") \
           and cert1.digest("sha256") == cert2.digest("sha256")


def read_certificate(path: Path) -> x509:
    if not path.exists() or not path.is_file():
        raise ValueError(f'Specified file does not exist: {path}')
    cert_bytes = path.read_bytes()
    cert = x509.load_pem_x509_certificate(cert_bytes, default_backend())
    return cert


def get_msca_root_cert(hostname: str, username: str, password: str) -> x509:

    # Parameters
    protocol = 'https'
    path = '/certsrv/certnew.cer?ReqID=CACert&Renewal=0&Mode=inst&Enc=b64'

    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    response = requests.get(f'{protocol}://{hostname}{path}', verify=False, auth=(username, password))
    if response.status_code != 200:
        raise RuntimeError(f'Failed to get CA certificate HTTP code: {response.status_code}')
    crt_bytes = response.text.encode('utf-8')
    crt = x509.load_pem_x509_certificate(crt_bytes, default_backend())
    return crt


def check_crt_key_match(ca_crt: x509, ca_key: x509):
    ca_key_public = ca_key.public_key()
    verifier = ca_key_public.verifier(
        signature=ca_crt.signature,
        padding=padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH),
        algorithm=hashes.SHA256())
    verifier.update(ca_crt.tbs_certificate_bytes)
    try:
        verifier.verify()
    except InvalidSignature:
        return False
    return True


def generate_ca_cert(ca_crt: str,  ca_key: str, organization: str, unit: str, locality: str, state: str, country: str,
                     validity: int, key_length: int, verbose: bool):

    today = datetime.datetime.today()
    one_day = datetime.timedelta(days=1)
    one_year = datetime.timedelta(days=validity)
    ca_cn = f'CA-{uuid.uuid1()}'
    email = f'nobody@{ca_cn}'
    serial = x509.random_serial_number()
    name = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, ca_cn),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, unit),
        x509.NameAttribute(NameOID.LOCALITY_NAME, locality),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, state),
        x509.NameAttribute(NameOID.COUNTRY_NAME, country),
        x509.NameAttribute(NameOID.EMAIL_ADDRESS, email),
    ])

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
        x509.NameAttribute(NameOID.EMAIL_ADDRESS, email),
    ]))

    builder = builder.issuer_name(name)
    builder = builder.not_valid_before(today - one_day)
    builder = builder.not_valid_after(today + one_year)
    builder = builder.serial_number(serial)
    builder = builder.public_key(public_key)

    # X509v3 Basic Constraints
    builder = builder.add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)

    # X509v3 Subject Key Identifier
    builder = builder.add_extension(x509.SubjectKeyIdentifier.from_public_key(public_key), critical=False)

    # X509v3 Authority Key Identifier
    ki = x509.SubjectKeyIdentifier.from_public_key(private_key.public_key())
    builder = builder.add_extension(x509.AuthorityKeyIdentifier(key_identifier=ki.digest,
                                                                authority_cert_issuer=[x509.DirectoryName(name)],
                                                                authority_cert_serial_number=serial), critical=False)

    # X509v3 Key Usage: critical
    builder = builder.add_extension(x509.KeyUsage(digital_signature=True,
                                                  key_encipherment=True,
                                                  content_commitment=False,
                                                  data_encipherment=False,
                                                  key_agreement=False,
                                                  encipher_only=False,
                                                  decipher_only=False,
                                                  key_cert_sign=True,
                                                  crl_sign=False
                                                  ), critical=True)

    # X509v3 Extended Key Usage
    # ekus = [ExtendedKeyUsageOID.SERVER_AUTH, ExtendedKeyUsageOID.CLIENT_AUTH]
    # builder = builder.add_extension(x509.ExtendedKeyUsage(ekus), critical=False)

    # X509v3 Subject Alternative Name
    builder = builder.add_extension(x509.SubjectAlternativeName([x509.DNSName(ca_cn)]), critical=False)

    # X509v3 Issuer Alternative Name
    builder = builder.add_extension(x509.IssuerAlternativeName([x509.RFC822Name(email)]), critical=False)

    certificate = builder.sign(private_key=private_key, algorithm=hashes.SHA256(), backend=default_backend())

    with Path(ca_key) as file:
        ca_key_bytes = private_key.private_bytes(encoding=serialization.Encoding.PEM,
                                                 format=serialization.PrivateFormat.PKCS8,
                                                 encryption_algorithm=serialization.NoEncryption())
        file.write_bytes(ca_key_bytes)

    with Path(ca_crt) as file:
        ca_crt_bytes = certificate.public_bytes(encoding=serialization.Encoding.PEM)
        file.write_bytes(ca_crt_bytes)


def create_cert_config(host: str,
                       country: str = 'US',
                       state: str = 'California',
                       locality: str = 'Palo Alto',
                       org: str = 'VMware') -> str:

    if '.' in host:
        hostname = host.split('.', 1)[0]
        hostname = f', DNS:{hostname}'
    else:
        hostname = ''

    try:
        ip = socket.gethostbyname(host)
        ip = f', IP:{ip}'
    except socket.gaierror:
        ip = ''

    config = (
        f'[ req ]\n'
        f'default_bits = 2048\n'
        f'default_keyfile = rui.key\n'
        f'distinguished_name = req_distinguished_name\n'
        f'encrypt_key = no\n'
        f'prompt = no\n'
        f'string_mask = nombstr\n'
        f'req_extensions = v3_req\n'
        f'\n'
        f'[ v3_req ]\n'
        f'basicConstraints = CA:FALSE\n'
        f'keyUsage = digitalSignature, keyEncipherment, dataEncipherment\n'
        f'extendedKeyUsage = serverAuth, clientAuth\n'
        f'subjectAltName = DNS:{host}{hostname}{ip}\n'
        f'\n'
        f'[ req_distinguished_name ]\n'
        f'C = {country}\n'
        f'ST = {state}\n'
        f'L = {locality}\n'
        f'O = {org}\n'
        f'CN = {host}\n'
    )
    return config


def create_openssl_config(host: str,
                          country: str = 'US',
                          state: str = 'California',
                          locality: str = 'Palo Alto',
                          org: str = 'VMware',
                          cn: str = 'CA') -> str:
    config = (
        f'[ req ]\n'
        f'default_bits = 2048\n'
        f'default_keyfile = ca.key\n'
        f'distinguished_name = req_distinguished_name\n'
        f'prompt = no\n'
        f'req_extensions = v3_req\n'
        f'x509_extensions = v3_ca\n'
        f'\n'
        f'[ req_distinguished_name ]\n'
        f'C = {country}\n'
        f'ST = {state}\n'
        f'L = {locality}\n'
        f'O = {org}\n'
        f'CN = {cn}\n'
        f'emailAddress = root@{host}\n'
        f'\n'
        f'[ v3_req ]\n'
        f'basicConstraints = CA:FALSE\n'
        f'keyUsage = digitalSignature, nonRepudiation, keyEncipherment\n'
        f'subjectAltName = DNS:{host}\n'
        f'issuerAltName = issuer:copy\n'
        f'\n'
        f'[ v3_ca ]\n'
        f'subjectKeyIdentifier=hash\n'
        f'authorityKeyIdentifier=keyid:always,issuer:always\n'
        f'subjectAltName = email:copy\n'
        f'issuerAltName = issuer:copy\n'
    )
    return config
