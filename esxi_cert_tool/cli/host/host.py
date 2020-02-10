from pathlib import Path

import click
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import load_pem_private_key

from esxi_cert_tool.cert_tool_esxi import CertToolEsxi


@click.group()
def host():
    pass


@host.command('msca')
@click.option('--esx-server', type=str, required=True, help=f'ESXi server')
@click.option('--esx-user', type=str, required=True, help=f'ESXi SSH username')
@click.option('--esx-pass', type=str, required=True, help=f'ESXi SSH password')
@click.option('--ca-server', type=str, required=True, help=f'Microsoft CA server')
@click.option('--ca-user', type=str, required=True, help=f'Microsoft CA username')
@click.option('--ca-pass', type=str, required=True, help=f'Microsoft CA password')
@click.option('--output-folder', type=click.Path(), default='./certs', help=f'Output folder')
@click.option('--verbose', is_flag=True, help=f'Print lots of output')
def cluster_msca(esx_server: str, esx_user: str, esx_pass: str, ca_server: str, ca_user: str, ca_pass: str,
                 output_folder: str, verbose: bool):

    # Deploying new crt and key
    print(f'Deploying new certificate on host {esx_server} using Microsoft CA {ca_server}')
    cte = CertToolEsxi(esx_server=esx_server,
                       esx_user=esx_user,
                       esx_pass=esx_pass,
                       output_folder=Path(output_folder),
                       verbose=verbose)
    cte.install_msca_signed(ca_server=ca_server, ca_user=ca_user, ca_pass=ca_pass)

    # Success
    print('Certificate installation successful')


@host.command('selfsigned')
@click.option('--esx-server', type=str, required=True, help=f'ESXi server')
@click.option('--esx-user', type=str, required=True, help=f'ESXi SSH username')
@click.option('--esx-pass', type=str, required=True, help=f'ESXi SSH password')
@click.option('--ca-crt', type=click.Path(exists=True), required=True, help=f'SSL cert')
@click.option('--ca-key', type=click.Path(exists=True), required=True, help=f'SSL key')
@click.option('--output-folder', type=click.Path(), default='./certs', help=f'Output folder')
@click.option('--verbose', is_flag=True, help=f'Print lots of output')
def cluster_selfsigned(esx_server: str, esx_user: str, esx_pass: str, ca_key: str, ca_crt: str, output_folder: str,
                       verbose: bool):

    # Check and load CA certificate
    print('Loading CA certificate')
    ca_crt_path = Path(ca_crt)
    ca_crt_bytes = ca_crt_path.read_bytes()
    ca_crt_x509 = x509.load_pem_x509_certificate(ca_crt_bytes, default_backend())

    # Check CA key
    print('Loading CA key')
    ca_key_path = Path(ca_key)
    ca_key_bytes = ca_key_path.read_bytes()
    ca_key_x509 = load_pem_private_key(ca_key_bytes, password=None, backend=default_backend())

    # Deploying new crt and key
    print(f'Generating new certificate and key for host {esx_server}')
    cte = CertToolEsxi(esx_server=esx_server,
                       esx_user=esx_user,
                       esx_pass=esx_pass,
                       output_folder=Path(output_folder),
                       verbose=verbose)
    cte.install_selfsigned(ca_crt=ca_crt_x509, ca_key=ca_key_x509)

    # Success
    print('Certificate installation successful')
