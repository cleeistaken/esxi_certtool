import socket

from pyVmomi import vim
from pyVim.connect import Disconnect, SmartStubAdapter, VimSessionOrientedStub
from typing import List
from esxi_cert_tool.vsanapiutils import WaitForTasks

from esxi_cert_tool.utils_ssl import unverified_ssl_context


class VcClusterException(Exception):
    pass


class ObjectNotFoundError(VcClusterException):
    """Exception raised if an object cannot be found."""
    pass


class TooManyObjectsError(VcClusterException):
    """Exception raised if there are many objects so a default cannot be chosen"""
    pass


class NoObjectsFoundError(VcClusterException):
    """Exception raised if there are no objects so a default cannot be chosen"""
    pass


class VcCluster(object):

    def __init__(self,
                 hostname: str,
                 username: str,
                 password: str,
                 datacenter: str = None,
                 cluster: str = None,
                 port: int = 443):
        """ Create a VcCluster instance """

        # Instance variables
        self.hostname = hostname
        self.username = username
        self.password = password
        self.port = port

        # Instance parameters
        self.ssl_context = unverified_ssl_context()
        self.timeout = 0

        try:
            # Connect using a session oriented connection
            # Ref. https://github.com/vmware/pyvmomi/issues/347
            self.si = None
            credentials = VimSessionOrientedStub.makeUserLoginMethod(self.username, self.password)
            smart_stub = SmartStubAdapter(host=self.hostname,
                                          port=self.port,
                                          sslContext=self.ssl_context,
                                          connectionPoolTimeout=self.timeout)
            self.session_stub = VimSessionOrientedStub(smart_stub, credentials)
            self.si = vim.ServiceInstance('ServiceInstance', self.session_stub)

            if not self.si:
                msg = f'Could not connect to the specified host using the specified username and password'
                raise ValueError(msg)

        except socket.gaierror as e:
            msg = f'Connection: failed ({e.strerror})'
            raise ValueError(msg)

        except IOError as e:
            raise e

        except Exception as e:
            raise e

        self.host_type = self.si.content.about.apiType
        if self.host_type != 'VirtualCenter':
            raise ValueError(f'Host is not a vCenter: {self.host_type}')

        self.api_version = self.si.content.about.apiVersion
        if int(self.api_version.split('.')[0]) < 6:
            raise RuntimeError(f'API version less than 6.0.0 is not supported: {self.api_version}')

        # Get objects
        self.datacenter = self.__get_datacenter(name=datacenter)
        self.cluster = self.__get_cluster(name=cluster)
        self.hosts = self.get_cluster_hosts()

    def __del__(self):
        if self.si:
            Disconnect(self.si)

    def __repr__(self):
        return(f'hostname: {self.hostname}:{self.port}, '
               f'username: {self.username}, '
               f'datacenter: {self.datacenter.name}, '
               f'cluster: {self.cluster.name}, '
               f'hosts: {", ".join([host.name for host in self.hosts])}')

    @property
    def datacenter(self) -> vim.Datacenter:
        return self.__datacenter

    @datacenter.setter
    def datacenter(self, value: vim.Datacenter):
        if not isinstance(value, vim.Datacenter):
            raise ValueError(f'Value not of type vim.Datacenter: {type(value)}')
        self.__datacenter = value

    @property
    def cluster(self) -> vim.ClusterComputeResource:
        return self.__cluster

    @cluster.setter
    def cluster(self, value: vim.ClusterComputeResource):
        if not isinstance(value, vim.ClusterComputeResource):
            raise ValueError(f'Value not of type vim.ClusterComputeResource: {type(value)}')
        self.__cluster = value

    @property
    def hosts(self) -> List[vim.HostSystem]:
        return self.__hosts

    @hosts.setter
    def hosts(self, value: vim.HostSystem):
        if not isinstance(value, List):
            raise ValueError(f'Value not of type vim.HostSystem: {type(value)}')
        self.__hosts = value

    def get_objs(self, vim_type: list, root, recursive: bool = True):
        """Get all object of a given type"""
        container = self.si.content.viewManager.CreateContainerView(container=root,
                                                                    type=vim_type,
                                                                    recursive=recursive)
        view = container.view
        container.Destroy()
        return view

    def find_obj_type(self, name: str, vim_type: List, root):
        objs = self.get_objs(vim_type, root)
        return self.find_obj(name=name, objs=objs)

    @staticmethod
    def find_obj(name: str, objs):
        if name:
            try:
                return next(obj for obj in objs if obj.name == name)
            except StopIteration:
                raise ObjectNotFoundError(f'Could not find object with name {name}')
        else:
            if len(objs) > 1:
                raise TooManyObjectsError(f'Please specify name: {", ".join([x.name for x in objs])}')
            elif len(objs) == 0:
                raise NoObjectsFoundError(f'No objects in list')
            return objs[0]

    def __get_datacenter(self, name: str) -> vim.Datacenter:
        """Returns the target datacenter object"""
        try:
            return self.find_obj_type(name=name, vim_type=[vim.Datacenter], root=self.si.content.rootFolder)
        except ObjectNotFoundError:
            raise ValueError(f'Unable to find datacenter: {name}')
        except TooManyObjectsError as e:
            raise ValueError(f'Could not select a default datacenter: {e}')
        except NoObjectsFoundError:
            raise ValueError(f'Could not find any datacenter on: {self.hostname}')

    def __get_cluster(self, name: str) -> vim.ClusterComputeResource:
        """Returns the target cluster object"""
        try:
            return self.find_obj_type(name=name, vim_type=[vim.ClusterComputeResource], root=self.datacenter.hostFolder)
        except ObjectNotFoundError:
            raise ValueError(f'Unable to find cluster: {name}')
        except TooManyObjectsError as e:
            raise ValueError(f'Could not select a default cluster: {e}')
        except NoObjectsFoundError:
            raise ValueError(f'Could not find any clusters in datacenter: {self.datacenter.name}')

    def get_vcenter_information(self) -> vim.AboutInfo:
        return self.si.content.about

    def get_cluster_hosts(self) -> List[vim.HostSystem]:
        """Get all the hosts in the target cluster"""
        return self.get_objs([vim.HostSystem], self.cluster)

    def wait_for_tasks(self, tasks: List[vim.Task]) -> None:
        WaitForTasks(tasks, self.si)
