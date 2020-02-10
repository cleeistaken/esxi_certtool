import click

from esxi_cert_tool import __version__, __date__
from esxi_cert_tool.cli.cluster import cluster
from esxi_cert_tool.cli.host import host
from esxi_cert_tool.cli.generate import generate


@click.group()
@click.version_option(version=__version__)
def cli():
    click.echo(f'esxi_cert_tool v{__version__} ({__date__})')


# Add click sub-command groups
cli.add_command(cluster.cluster)
cli.add_command(generate.generate)
cli.add_command(host.host)
