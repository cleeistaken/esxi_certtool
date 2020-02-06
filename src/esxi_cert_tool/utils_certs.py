
import requests
import urllib3

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
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
