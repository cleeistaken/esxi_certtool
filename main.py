from enum import Enum

from cert_tool_esxi import CertToolEsx


class CertOperation(Enum):
    self_signed = 1
    msca = 2


def main():

    operation = CertOperation.msca

    vc_server = ''
    vc_user = 'administrator@vsphere.local'
    vc_pass = ''
    vc_datacenter = ''
    vc_cluster = ''
    vc_ssh_user = ''
    vc_ssh_pass = ''

    esx_user = 'root'
    esx_pass = ''

    ca_server = ''
    ca_user = 'administrator'
    ca_pass = ''

    cte = CertToolEsx(vc_server=vc_server,
                      vc_user=vc_user,
                      vc_pass=vc_pass,
                      vc_datacenter=vc_datacenter,
                      vc_cluster=vc_cluster,
                      vc_ssh_user=vc_ssh_user,
                      vc_ssh_pass=vc_ssh_pass,
                      esx_user=esx_user,
                      esx_pass=esx_pass,
                      verbose=True)

    if operation == CertOperation.self_signed:
        print(f'Deploying self-signed certificates')
        cte.install_self_signed_to_esxi()

    elif operation == CertOperation.msca:
        print(f'Deploying Microsoft CA certificates')
        cte.install_msca_cert_to_esxi(ca_server=ca_server, ca_user=ca_user, ca_pass=ca_pass)


if __name__ == "__main__":
    main()
