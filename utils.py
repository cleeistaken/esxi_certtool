import progressbar
import socket
import ssl
import subprocess
import urllib3
import requests

from cryptography import x509
from OpenSSL.crypto import load_certificate, FILETYPE_PEM
from pathlib import Path
from time import sleep


def get_msca_root_cert(hostname: str, username: str, password: str) -> str:
    protocol = 'https'
    path = '/certsrv/certnew.cer?ReqID=CACert&Renewal=0&Mode=inst&Enc=b64'
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    response = requests.get(f'{protocol}://{hostname}{path}', verify=False, auth=(username, password))
    if response.status_code != 200:
        raise RuntimeError(f'Failed to get CA certificate HTTP code: {response.status_code}')
    return response.text


def unverified_ssl_context() -> ssl.SSLContext:
    """
    Create an SSLContext with host and certificate verification disabled.
    """
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return context


def ping(hostname: str) -> bool:
    """
    Returns True if host (str) responds to a ping request.
    Remember that a host may not respond to a ping (ICMP) request even if the host name is valid.

    Ref.
    https://stackoverflow.com/questions/28769023/get-output-of-system-ping-without-printing-to-the-console
    https://docs.python.org/3/library/subprocess.html
    """
    try:
        cmd = ['ping', '-c', '1', '-W', '1', hostname]
        subprocess.check_call(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return True
    except subprocess.CalledProcessError:
        return False


def host_down(hostname: str, max_tries: int = 300):
    required_consecutive = 5
    consecutive = required_consecutive
    with progressbar.ProgressBar(max_value=max_tries) as bar:
        for i in range(max_tries):
            bar.update(i)
            sleep(1)
            status = ping(hostname)
            if not status:  # wait for host NOT to respond
                consecutive -= 1
            else:
                consecutive = required_consecutive
            if consecutive < 1:
                return
    raise RuntimeError(f'Host still responding after {max_tries} seconds')


def host_up(hostname: str, max_tries: int = 300):
    required_consecutive = 5
    consecutive = required_consecutive
    with progressbar.ProgressBar(max_value=max_tries) as bar:
        for i in range(max_tries):
            bar.update(i)
            sleep(1)
            status = ping(hostname)
            if status:  # wait for host to respond
                consecutive -= 1
            else:
                consecutive = required_consecutive
            if consecutive < 1:
                return
    raise RuntimeError(f'Host not responding after after {max_tries} seconds')


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
    except:
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


def compare_certs(cert1: x509, cert2: x509) -> bool:
    return cert1.digest("md5") == cert2.digest("md5") \
           and cert1.digest("sha1") == cert2.digest("sha1") \
           and cert1.digest("sha256") == cert2.digest("sha256")


def read_certificate(path: Path, file_type=FILETYPE_PEM) -> x509:
    if not path.exists() or not path.is_file():
        raise ValueError(f'Specified file does not exist: {path}')
    return load_certificate(file_type, path.read_bytes())
