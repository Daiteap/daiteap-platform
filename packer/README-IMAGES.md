# Readme - building custom Daiteap images

Instructions to build custom Daiteap images using packer.io

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
