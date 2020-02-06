import socket


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


