from setuptools import setup

from esxi_cert_tool import __title__, __version__, __url__, __license__, __author__, __author_email__, __description__

setup(
    name=__title__,
    version=__version__,
    packages=['esxi_cert_tool', 'esxi_cert_tool.cli', 'esxi_cert_tool.cli.host', 'esxi_cert_tool.cli.cluster',
              'esxi_cert_tool.cli.generate'],
    url=__url__,
    license=__license__,
    author=__author__,
    author_email=__author_email__,
    description=__description__
)
