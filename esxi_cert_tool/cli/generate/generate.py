import click

from esxi_cert_tool.utils_certs import generate_ca_cert


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
def generate_ca(ca_crt: str,  ca_key: str, organization: str, unit: str, locality: str, state: str, country: str,
                validity: int, key_length: int, verbose: bool):

    print(f'Generating a new CA certificate and key')
    if verbose:
        print(f' Certificate: {ca_crt}\n'
              f' Key        : {ca_key}\n'
              f' Validity   : {validity}\n'
              f' Key length : {key_length}\n'
              f' C          : {country}\n'
              f' ST         : {state}\n'
              f' L          : {locality}\n'
              f' O          : {organization}\n'
              f' U          : {unit}')
    generate_ca_cert(ca_crt=ca_crt,
                     ca_key=ca_key,
                     organization=organization,
                     unit=unit,
                     locality=locality,
                     state=state,
                     country=country,
                     validity=validity,
                     key_length=key_length,
                     verbose=verbose)

    print(f'CA certificate and key successfully generated')
