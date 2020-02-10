from pathlib import Path

import click
from cryptography.hazmat.backends import default_backend
from cryptography import x509
from cryptography.hazmat.primitives.serialization import load_pem_private_key

from esxi_cert_tool.cert_tool_cluster import CertToolCluster
from esxi_cert_tool.cert_tool_sddc import CertToolSddc
from esxi_cert_tool.cert_tool_vc import CertToolVc
from esxi_cert_tool.utils_certs import get_msca_root_cert


@click.group()
def cluster():
    pass


@cluster.command('msca')
@click.option('--sddc_server', type=str, required=True, help=f'SDDC server')
@click.option('--sddc_user', type=str, required=True, help=f'SDDC username')
@click.option('--sddc_pass', type=str, required=True, help=f'SDDC password')
@click.option('--vc_server', type=str, required=True, help=f'vCenter server')
@click.option('--vc_user', type=str, required=True, help=f'vCenter username')
@click.option('--vc_pass', type=str, required=True, help=f'vCenter password')
@click.option('--vc_datacenter', type=str, required=True, help=f'vCenter datacenter')
@click.option('--vc_cluster', type=str, required=True, help=f'vCenter cluster')
@click.option('--vc_ssh_user', type=str, required=True, help=f'vCenter SSH user')
@click.option('--vc_ssh_pass', type=str, required=True, help=f'vCenter SSH password')
@click.option('--esx_ssh_user', type=str, required=True, help=f'ESXi SSH username')
@click.option('--esx_ssh_pass', type=str, required=True, help=f'ESXi SSH password')
@click.option('--ca_server', type=str, required=True, help=f'Microsoft CA server')
@click.option('--ca_user', type=str, required=True, help=f'Microsoft CA username')
@click.option('--ca_pass', type=str, required=True, help=f'Microsoft CA password')
@click.option('--verbose', is_flag=True, help=f'Print lots of output')
def cluster_msca(sddc_server: str,  sddc_user: str, sddc_pass: str, vc_server: str, vc_user: str,
                 vc_pass: str, vc_datacenter: str, vc_cluster: str, vc_ssh_user: str, vc_ssh_pass: str,
                 esx_ssh_user: str, esx_ssh_pass: str, ca_server: str, ca_user: str, ca_pass: str, verbose: bool):

    # Get Microsoft CA root certificate
    print('Getting Microsoft CA root certificate')
    ca_crt_x509 = get_msca_root_cert(hostname=ca_server, username=ca_user, password=ca_pass)

    # Add certificate to SDDC manager
    print('Adding Microsoft CA root certificate to the SDDC manager key stores')
    cts = CertToolSddc(sddc_server=sddc_server,
                       sddc_user=sddc_user,
                       sddc_pass=sddc_pass,
                       verbose=verbose)
    cts.add_cert(ca_crt_x509)

    # Add certificate to vCenter
    print('Adding Microsoft CA root certificate to the vCenter trusted certs')
    ctv = CertToolVc(vc_server=vc_server,
                     vc_user=vc_user,
                     vc_pass=vc_pass,
                     vc_ssh_user=vc_ssh_user,
                     vc_ssh_pass=vc_ssh_pass,
                     verbose=verbose)
    ctv.add_cert(ca_crt_x509)

    try:
        print(f'Connecting to vCenter')
        cte = CertToolCluster(vc_server=vc_server,
                              vc_user=vc_user,
                              vc_pass=vc_pass,
                              vc_datacenter=vc_datacenter,
                              vc_cluster=vc_cluster,
                              vc_ssh_user=vc_ssh_user,
                              vc_ssh_pass=vc_ssh_pass,
                              esx_user=esx_ssh_user,
                              esx_pass=esx_ssh_pass,
                              verbose=verbose)

        print(f'Deploying Microsoft CA certificates to ESXi hosts')
        cte.install_msca_cert_to_esxi(ca_server=ca_server, ca_user=ca_user, ca_pass=ca_pass)

    except ValueError as e:
        print(f'Failed to replace certificates because on an invalid input error: {e}')

    except RuntimeError as e:
        print(f'Failed to replace certificates because on a runtime error: {e}')

    except Exception as e:
        print(f'Failed to replace certificates because on an invalid input error: {e}')

    pass


@cluster.command('selfsigned')
@click.option('--sddc_server', type=str, required=True, help=f'SDDC server')
@click.option('--sddc_user', type=str, required=True, help=f'SDDC username')
@click.option('--sddc_pass', type=str, required=True, help=f'SDDC password')
@click.option('--vc_server', type=str, required=True, help=f'vCenter server')
@click.option('--vc_user', type=str, required=True, help=f'vCenter username')
@click.option('--vc_pass', type=str, required=True, help=f'vCenter password')
@click.option('--vc_datacenter', type=str, required=True, help=f'vCenter datacenter')
@click.option('--vc_cluster', type=str, required=True, help=f'vCenter cluster')
@click.option('--vc_ssh_user', type=str, required=True, help=f'vCenter SSH user')
@click.option('--vc_ssh_pass', type=str, required=True, help=f'vCenter SSH password')
@click.option('--esx_ssh_user', type=str, required=True, help=f'ESXi SSH username')
@click.option('--esx_ssh_pass', type=str, required=True, help=f'ESXi SSH password')
@click.option('--ca-key', type=click.Path(exists=True), required=True, help=f'SSL key')
@click.option('--ca-crt', type=click.Path(exists=True), required=True, help=f'SSL cert')
@click.option('--verbose', is_flag=True, help=f'Print lots of output')
def cluster_selfsigned(sddc_server: str,  sddc_user: str, sddc_pass: str, vc_server: str, vc_user: str,
                       vc_pass: str, vc_datacenter: str, vc_cluster: str,  vc_ssh_user: str, vc_ssh_pass: str,
                       esx_ssh_user: str, esx_ssh_pass: str, ca_key: str, ca_crt: str, verbose: bool):

    # Check and load CA certificate
    ca_crt_path = Path(ca_crt)
    ca_crt_bytes = ca_crt_path.read_bytes()
    ca_crt_x509 = x509.load_pem_x509_certificate(ca_crt_bytes, default_backend())

    # Check CA key
    ca_key_path = Path(ca_key)
    ca_key_bytes = ca_key_path.read_bytes()
    ca_key_x509 = load_pem_private_key(ca_key_bytes, password=None, backend=default_backend())

    # Add certificate to SDDC manager
    print('Adding CA root certificate to the SDDC manager key stores')
    cts = CertToolSddc(sddc_server=sddc_server,
                       sddc_user=sddc_user,
                       sddc_pass=sddc_pass,
                       verbose=verbose)
    cts.add_cert(ca_crt_x509)

    # Add certificate to vCenter
    print('Adding Microsoft CA root certificate to the vCenter trusted certs')
    ctv = CertToolVc(vc_server=vc_server,
                     vc_user=vc_user,
                     vc_pass=vc_pass,
                     vc_ssh_user=vc_ssh_user,
                     vc_ssh_pass=vc_ssh_pass,
                     verbose=verbose)
    ctv.add_cert(ca_crt_x509)

    try:
        print(f'Connecting to vCenter')
        cte = CertToolCluster(vc_server=vc_server,
                              vc_user=vc_user,
                              vc_pass=vc_pass,
                              vc_datacenter=vc_datacenter,
                              vc_cluster=vc_cluster,
                              vc_ssh_user=vc_ssh_user,
                              vc_ssh_pass=vc_ssh_pass,
                              esx_user=esx_ssh_user,
                              esx_pass=esx_ssh_pass,
                              verbose=verbose)

        print(f'Deploying self-signed certificates')
        cte.install_self_signed_to_esxi(ca_crt=ca_crt_x509, ca_key=ca_key_x509)

    except ValueError as e:
        print(f'Failed to replace certificates because on an invalid input error: {e}')

    except RuntimeError as e:
        print(f'Failed to replace certificates because on a runtime error: {e}')

    except Exception as e:
        print(f'Failed to replace certificates because on an invalid input error: {e}')




