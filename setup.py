from setuptools import setup

from lib import __title__, __version__, __url__, __license__, __author__, __author_email__, __description__

setup(
    name=__title__,
    version=__version__,
    packages=['lib', 'lib.esxi_cert_tool', 'lib.esxi_cert_tool.host', 'lib.esxi_cert_tool.cluster',
              'lib.esxi_cert_tool.generate'],
    url=__url__,
    license=__license__,
    author=__author__,
    author_email=__author_email__,
    description=__description__
)
