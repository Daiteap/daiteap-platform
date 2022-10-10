packer {
  required_plugins {
    amazon = {
      version = ">= 0.0.1"
      source  = "github.com/hashicorp/amazon"
    }
    googlecompute = {
      version = ">= 0.0.1"
      source = "github.com/hashicorp/googlecompute"
    }
    azure-arm = {
      version = ">= 0.0.1"
      source = "github.com/hashicorp/azure"
    }
  }
}

variable "ami_prefix" {
  type    = string
  default = "dlcm-ubuntu-1804"
}

variable "aws_access_key" {
  type    = string
}

variable "aws_secret_key" {
  type    = string
}

variable "azure_client_id" {
  type    = string
}

variable "azure_client_secret" {
  type    = string
}

variable "azure_subscription_id" {
  type    = string
}

variable "azure_tenant_id" {
  type    = string
}

variable "inline_commands" {
  type    = list(string)
  default = [
    "curl -s https://packages.cloud.google.com/apt/doc/apt-key.gpg | sudo apt-key add -",
    "cat <<EOF | sudo tee /etc/apt/sources.list.d/kubernetes.list\ndeb https://apt.kubernetes.io/ kubernetes-xenial main\nEOF",
    "sudo sed -i '/^# deb.*multiverse/ s/^# //' /etc/apt/sources.list",
    "sudo apt-get update",
    "sudo apt-get install --allow-downgrades --allow-change-held-packages -y containerd kubeadm kubectl apt-transport-https curl kubelet=1.23.2-00",
    "sudo apt-mark hold kubelet kubeadm kubectl",
    "sudo swapoff -a",
    "sudo sed -i '/ swap / s/^(.*)$/#1/g' /etc/fstab",
    "sudo apt-get install -y aufs-tools ca-certificates curl dbus dnsmasq fail2ban libstrongswan libstrongswan-standard-plugins nfs-common openssl python3 python3-pip resolvconf strongswan strongswan-charon",
    "sudo apt-get install -y firewalld net-tools",
    "sudo systemctl start firewalld",
    "sudo systemctl enable firewalld",
    "sudo systemctl disable ufw",
    "sudo systemctl stop ufw",
    "sudo firewall-cmd --add-source=10.0.0.0/8 --zone=trusted --permanent",
    "sudo firewall-cmd --add-source=172.16.0.0/12 --zone=trusted --permanent",
    "sudo firewall-cmd --add-source=192.168.0.0/16  --zone=trusted --permanent",
    "sudo firewall-cmd --add-service=ssh --zone=drop --permanent",
    "sudo firewall-cmd --zone=drop --add-service=ipsec --permanent",
    "sudo firewall-cmd --zone=drop --add-port=4500/udp --permanent",
    "sudo firewall-cmd --add-port=6443/tcp --zone=drop --permanent",
    "sudo firewall-cmd --set-default-zone=drop",
    "sudo systemctl restart firewalld",
    "cat <<EOF | sudo tee /etc/modules-load.d/containerd.conf\noverlay\nbr_netfilter\nEOF",
    "sudo modprobe overlay",
    "sudo modprobe br_netfilter",
    "cat <<EOF | sudo tee /etc/sysctl.d/99-kubernetes-cri.conf \nnet.bridge.bridge-nf-call-iptables = 1 \nnet.ipv4.ip_forward = 1\nnet.bridge.bridge-nf-call-ip6tables = 1\nEOF",
    "sudo sysctl --system",
    "sudo mkdir -p /etc/containerd",
    "sudo containerd config default | sudo tee /etc/containerd/config.toml",
    "sudo systemctl restart containerd",
  ]
}

source "amazon-ebs" "ubuntu" {
  ami_name      = "${var.ami_prefix}"
  instance_type = "t2.micro"
  region        = "eu-central-1"
  access_key = "${var.aws_access_key}"
  secret_key = "${var.aws_secret_key}"
  ami_groups = ["all"]
  ami_regions = [
    "eu-central-1",
    "eu-north-1",
    "ap-south-1",
    "eu-west-3",
    "eu-west-2",
    "eu-west-1",
    "us-east-1",
    "us-east-2",
    "us-west-1",
    "us-west-2"
  ]

  source_ami_filter {
    filters = {
      name                = "ubuntu/images/hvm-ssd/ubuntu-bionic-18.04-amd64-server-*"
      root-device-type    = "ebs"
      virtualization-type = "hvm"
    }
    most_recent = true
    owners      = ["099720109477"]
  }
  ssh_username = "ubuntu"
}

build {
  name    = "test-packer"
  sources = [
    "source.amazon-ebs.ubuntu"
  ]

  provisioner "shell" {
    environment_vars = [
      "CUSTOM_TEXT=Daiteap",
    ]
    inline = "${var.inline_commands}"
  }
}

source "googlecompute" "basic-example" {
  project_id = "daiteapdevplayground"
  zone = "europe-west3-a"
  // source_image = "ubuntu-1804-bionic-*"
  source_image_family = "ubuntu-1804-lts"
  ssh_username = "ubuntu"
  image_name = "dlcm-ubuntu-1804"
}

build {
  sources = ["sources.googlecompute.basic-example"]

  provisioner "shell" {
    environment_vars = [
      "CUSTOM_TEXT=Daiteap",
    ]
    inline = "${var.inline_commands}"
  }
}

source "azure-arm" "basic-example" {
  client_id = "${var.azure_client_id}"
  client_secret = "${var.azure_client_secret}"
  subscription_id = "${var.azure_subscription_id}"
  tenant_id = "${var.azure_tenant_id}"

  os_type = "Linux"
  image_publisher = "Canonical"
  image_offer = "UbuntuServer"
  image_sku = "18.04-LTS"

  managed_image_name = "dlcm-ubuntu-1804"
  managed_image_resource_group_name = "Packer"

  ssh_username = "clouduser"

  shared_image_gallery_destination {
    subscription = "af5bb549-d639-4ea4-9632-5b6aa6881cd8"
    resource_group = "Packer"
    gallery_name = "Packer_image_gallery"
    image_name = "dlcm-ubuntu-1804"
    image_version = "1.0.1"
    replication_regions = [
      "eastasia",
      "eastus",
      "eastus2",
      "westus",
      "northeurope",
      "westeurope",
      "australiaeast",
      "australiasoutheast",
      "westus2",
      "francecentral",
      "australiacentral",
      "switzerlandnorth",
      "germanywestcentral",
      "westus3",
      "swedencentral"
    ]
  }

  temp_resource_group_name = "packer-temp"
  location = "East US"
  vm_size = "Standard_DS2_v2"
}

build {
  sources = ["sources.azure-arm.basic-example"]

  provisioner "shell" {
    environment_vars = [
      "CUSTOM_TEXT=Daiteap",
    ]
    inline = "${var.inline_commands}"
  }
}
