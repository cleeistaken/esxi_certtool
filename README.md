# esxi_certtool
Simple python script that helps automate replacing ESXi certificates in a VCF environment.

## Requirements
* Python 3.7+

### Packages
* bcrypt==3.1.7
* certifi==2019.11.28
* certsrv==2.1.1
* cffi==1.13.2
* chardet==3.0.4
* Click==7.0
* cryptography==2.8
* fabric==2.5.0
* idna==2.8
* invoke==1.4.0
* paramiko==2.7.1
* progressbar2==3.47.0
* pycparser==2.19
* PyNaCl==1.3.0
* pyOpenSSL==19.1.0
* pysftp==0.2.9
* python-utils==2.3.0
* pyvmomi==6.7.3
* requests==2.22.0
* scp==0.13.2
* six==1.14.0
* urllib3==1.25.8


## Commands
### cluster
Used to operate on an entire vSphere cluster.


#### msca
Generates new certificate signing requests for all the ESXi host certificates in the target cluster, uses the
specified Microsoft Certificate Authority to sign the certificates, then installs the signed certificates on the hosts.
This commands checks to see if the Microsoft Certificate Authority root certificate is installed in the SDDC manager 
and vCenter, and adds the CA certificate if it is not in their keystore.

```shell script
cli.py cluster msca [OPTIONS]
Options:
  --sddc_server TEXT    SDDC server  [required] 
  --sddc_user TEXT      SDDC username  [required] 
  --sddc_pass TEXT      SDDC password  [required] 
  --vc_server TEXT      vCenter server  [required] 
  --vc_user TEXT        vCenter username  [required] 
  --vc_pass TEXT        vCenter password  [required] 
  --vc_datacenter TEXT  vCenter datacenter  [required]
  --vc_cluster TEXT     vCenter cluster  [required]
  --vc_ssh_user TEXT    vCenter SSH user  [required]
  --vc_ssh_pass TEXT    vCenter SSH password  [required]
  --esx_ssh_user TEXT   ESXi SSH username  [required]
  --esx_ssh_pass TEXT   ESXi SSH password  [required]
  --ca_server TEXT      Microsoft CA server  [required]
  --ca_user TEXT        Microsoft CA username  [required]
  --ca_pass TEXT        Microsoft CA password  [required]
  --verbose             Print lots of output
  --help                Show this message and exit.
```


#### selfsigned
Uses the provided CA certificate and key to generate and replace all the ESXi host certificates in the target cluster. 
Checks to see if the CA certificate is installed in the SDDC manager and vCenter, and adds the CA certificate if it is
not in their keystore.

``` shell script
Usage: esxi_cert_tool.py cluster selfsigned [OPTIONS]

Options:
  --sddc_server TEXT    SDDC server  [required]
  --sddc_user TEXT      SDDC username  [required]
  --sddc_pass TEXT      SDDC password  [required]
  --vc_server TEXT      vCenter server  [required]
  --vc_user TEXT        vCenter username  [required]
  --vc_pass TEXT        vCenter password  [required]
  --vc_datacenter TEXT  vCenter datacenter  [required]
  --vc_cluster TEXT     vCenter cluster  [required]
  --vc_ssh_user TEXT    vCenter SSH user  [required]
  --vc_ssh_pass TEXT    vCenter SSH password  [required]
  --esx_ssh_user TEXT   ESXi SSH username  [required]
  --esx_ssh_pass TEXT   ESXi SSH password  [required]
  --ca-key PATH         SSL key  [required]
  --ca-crt PATH         SSL cert  [required]
  --verbose             Print lots of output
  --help                Show this message and exit.

```


### Generate
Used to generate certificates or signing requests.


#### ca
Generates a CA certificate and key.
```shell script
Usage: cli.py generate ca [OPTIONS]

Options:
  --ca_crt PATH             Output file for the CA certificate
  --ca_key PATH             Output file for the CA key
  --organization TEXT       Certificate Organization
  --unit TEXT               Certificate Unit
  --locality TEXT           Certificate Locality
  --state TEXT              Certificate State or Province
  --country TEXT            Certificate Country
  --validity INTEGER RANGE  Number of days valid
  --key-length INTEGER      Private key size
  --verbose                 Print lots of output
  --help                    Show this message and exit.
```


### Host
Used to operate on a single ESXi host. Does not take into consideration the SDDC manager, vCenter, or cluster 
constructs such as vSAN or HA.


#### msca
Generates a certificate signing requests for the ESXi host, uses the specified Microsoft Certificate Authority to sign 
the certificate, then installs the signed certificates on the host.

```shell script
Usage: cli.py host msca [OPTIONS]

Options:
  --esx-server TEXT     ESXi server  [required]
  --esx-user TEXT       ESXi SSH username  [required]
  --esx-pass TEXT       ESXi SSH password  [required]
  --ca-server TEXT      Microsoft CA server  [required]
  --ca-user TEXT        Microsoft CA username  [required]
  --ca-pass TEXT        Microsoft CA password  [required]
  --output-folder PATH  Output folder
  --verbose             Print lots of output
  --help                Show this message and exit.

```


#### selfsigned
Uses the provided CA certificate and key to generate and replace the ESXi host certificate.

```shell script
Usage: cli.py host selfsigned [OPTIONS]

Options:
  --esx-server TEXT     ESXi server  [required]
  --esx-user TEXT       ESXi SSH username  [required]
  --esx-pass TEXT       ESXi SSH password  [required]
  --ca-crt PATH         SSL cert  [required]
  --ca-key PATH         SSL key  [required]
  --output-folder PATH  Output folder
  --verbose             Print lots of output
  --help                Show this message and exit.

```