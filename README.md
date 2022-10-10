# Daiteap daiteap-platform

Daiteap Cloud daiteap-platform is an open-source technology which allows developers and IT pros to create and manage multi-cloud resources in an easy and efficient manner. Those resources include Kubernetes clusters, Compute (VMs) and S3 storage.

This repository contains the backand and API for daiteap. 

# Installation

Follow the steps below to run Daiteap locally. 

Requirements:
- docker 
- GIT


[daiteap-ui](https://github.com/Daiteap/daiteap-ui) clone into the same folder where this repository is cloned

```shell
# clone daiteap-ui (make sure it is in the same directory as this repository)
git clone https://github.com/Daiteap/daiteap-ui

# clone and cd into this repository
git clone https://github.com/Daiteap/daiteap-platform
cd daiteap-platform

# build images
docker-compose build

# generate ssh keys
mkdir -p docker-compose/.ssh
ssh-keygen -o -a 100 -t rsa -f docker-compose/.ssh/id_rsa -C "user@server.com" -N "" -m PEM

# start daiteap locally
docker-compose -f docker-compose.yml --log-level DEBUG up

# Init environment (first start only)
sh docker-compose/init.sh

# Navigate to http://localhost:1899

```

## Tear-down commands
```shell
docker-compose down
sudo rm -rf docker-compose/.ssh
sudo rm -rf docker-compose/mysql
```

# Building custom cloud images
# Readme - building custom Daiteap images

Instructions to build custom Daiteap images using packer.io. All scripts are located in the [packer](./packer/) folder.

### Building images for AWS

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

### Building images for GCP

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

### Building images for Azure

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

### Building images for OpenStack
TODO:...


URL [daiteap.com](https://www.daiteap.com/)

[License Apache 2.0](./LICENSE)

