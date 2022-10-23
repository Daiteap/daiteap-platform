# daiteap-platform

daiteap-platform is the daiteap application logic which allows you to create and manage multi-cloud resources in an easy and efficient manner. 
Currently you can setup Kubernetes clusters, Compute (VMs) and S3 storage on one or multiple providers.

This repository contains the backend and API for daiteap. 

# Installation

Follow the steps below to run Daiteap locally (Linux, Windows WSL2). 

Requirements:
- docker/docker-compose
- GIT
- DNS zone in GCP (optional)

```shell
# clone daiteap-ui
git clone git@github.com:Daiteap/daiteap-ui.git

# clone and cd into this repository
git clone git@github.com:Daiteap/daiteap-platform.git
cd daiteap-platform

# generate ssh keys
mkdir -p docker-compose/.ssh
ssh-keygen -o -a 100 -t rsa -f docker-compose/.ssh/id_rsa -C "user@server.com" -N "" -m PEM
```

```shell
# Install jq
sudo apt-get install jq

Mac User can use alternatively
brew install jq

# Init environment (first start only - open new terminal, cd to ./daiteap-platform and do)
sh docker-compose/init.sh

# set VAULT_TOKEN variable
export VAULT_TOKEN=$(jq -r .root_token docker-compose/vault/vault-init.json)
```
___
### Start daiteap with DNS for Service Applications
Once you install an application from the service catalog you can access it by IP-Adress or using the DNS option to access the service by Domain Name.

#### Requirements:
- Existing [Google Cloud DNS Zone](https://cloud.google.com/dns/docs/zones#create-pub-zone)
- [Service account](https://cloud.google.com/iam/docs/creating-managing-service-accounts#creating) with [DNS Administrator](https://cloud.google.com/iam/docs/understanding-roles#dns-roles) permissions
- Service account key in JSON format

```shell
# replace docker-compose/daiteap_dns_credentials.json with your service account key
cp <path to service account key> docker-compose/daiteap_dns_credentials.json

# start daiteap
USE_DNS_FOR_SERVICES=True \
SERVICES_DNS_DOMAIN=<replace with dns zone domain> \
SERVICES_DNS_ZONE_NAME=<replace with zone name> \
docker-compose up -d
```

### Or
### Start daiteap without DNS for services
```shell
docker-compose up -d
```
___
### Unseal Vault (unseal after every restart)
```shell
docker exec daiteap-vault vault operator unseal $(jq -r .unseal_keys_b64[0] docker-compose/vault/vault-init.json)
```

### Navigate to http://localhost:1899

```shell
# (optional) see container logs
docker-compose logs -f

# (optional) check container state
docker-compose ps
```

## Tear-down commands
```shell
docker-compose down --rmi local -v
sudo rm -rf docker-compose/.ssh
sudo rm -rf docker-compose/mysql
sudo rm -rf docker-compose/vault/data
sudo rm -rf docker-compose/vault/vault-init.json
```

# Building custom cloud images

Instructions to build custom Daiteap images using packer.io. All scripts are located in the [packer](./packer/) folder.

#### Building images for AWS

Create packer user in AWS IAM and add required policies to build AMIs:
Policy:
- AmazonEC2FullAccess  
- AWSMarketplaceImageBuildFullAccess  
- IAMUserSSHKeys  
- EC2InstanceProfileForImageBuilder  
- AWSImageBuilderFullAccess  

Configure AWS access parameters:
```console
export AWS_ACCESS_KEY=XXXXXXXXXXX
export AWS_SECRET_KEY=YYYYYYYYYYY
```

Build and upload image to AWS
```console
packer init aws-ubuntu.pkr.hcl
packer validate -var aws_access_key=$AWS_ACCESS_KEY -var aws_secret_key=$AWS_SECRET_KEY aws-ubuntu.pkr.hcl
packer build -var aws_access_key=$AWS_ACCESS_KEY -var aws_secret_key=$AWS_SECRET_KEY aws-ubuntu.pkr.hcl
```

#### Building images for GCP

Configure GCP access parameters:
```console
export GOOGLE_APPLICATION_CREDENTIALS=/path/to/credentials.json
```

Build and upload image to GCP
```console
packer init google-ubuntu.pkr.hcl
packer validate google-ubuntu.pkr.hcl
packer build google-ubuntu.pkr.hcl
```

#### Building images for Azure

Configure Azure access parameters:
```console
export azure_tenant_id=XXX
export azure_subscription_id=YYY
export azure_client_id=ZZZ
export azure_client_secret=WWW
```

Build and upload image to Azure
```console
packer init azure-ubuntu.pkr.hcl
packer validate -var azure_client_id=$azure_client_id -var azure_client_secret=$azure_client_secret -var azure_subscription_id=$azure_subscription_id -var azure_tenant_id=$azure_tenant_id azure-ubuntu.pkr.hcl
packer build -var azure_client_id=$azure_client_id -var azure_client_secret=$azure_client_secret -var azure_subscription_id=$azure_subscription_id -var azure_tenant_id=$azure_tenant_id azure-ubuntu.pkr.hcl
```

#### Building images for OpenStack
TODO:


URL [daiteap.com](https://www.daiteap.com/)

[License Apache 2.0](./LICENSE)

