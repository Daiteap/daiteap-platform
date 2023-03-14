packer {
  required_plugins {
    azure-arm = {
      version = ">= 0.0.1"
      source = "github.com/hashicorp/azure"
    }
  }
}

variable "image_prefix" {
  type    = string
  default = "dlcm-ubuntu-1804"
}

variable "image_version" {
  type    = string
  default = "11"
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
    "sudo systemctl stop apt-daily.timer",
    "sudo systemctl disable apt-daily.timer",
    "sudo systemctl mask apt-daily.service",
    "sudo systemctl daemon-reload",
    "curl -s https://packages.cloud.google.com/apt/doc/apt-key.gpg | sudo apt-key add -",
    "cat <<EOF | sudo tee /etc/apt/sources.list.d/kubernetes.list\ndeb https://apt.kubernetes.io/ kubernetes-xenial main\nEOF",
    "sudo sed -i '/^# deb.*multiverse/ s/^# //' /etc/apt/sources.list",
    "sudo apt-get update",
    "sudo apt-get install -y aufs-tools ca-certificates curl dbus fail2ban libstrongswan libstrongswan-standard-plugins nfs-common openssl python3 python3-pip resolvconf strongswan strongswan-charon",
    "sudo apt-get install --allow-downgrades --allow-change-held-packages -y containerd kubeadm kubectl apt-transport-https kubelet=1.23.2-00",
    "sudo apt-mark hold kubelet kubeadm kubectl",
    "sudo swapoff -a",
    "sudo sed -i '/ swap / s/^(.*)$/#1/g' /etc/fstab",
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

source "azure-arm" "basic-example" {
  client_id = "${var.azure_client_id}"
  client_secret = "${var.azure_client_secret}"
  subscription_id = "${var.azure_subscription_id}"
  tenant_id = "${var.azure_tenant_id}"

  os_type = "Linux"
  image_publisher = "Canonical"
  image_offer = "UbuntuServer"
  image_sku = "18.04-LTS"

  os_disk_size_gb = "50"

  managed_image_name = "${var.image_prefix}"
  managed_image_resource_group_name = "Packer"

  ssh_username = "clouduser"

  shared_image_gallery_destination {
    subscription = "af5bb549-d639-4ea4-9632-5b6aa6881cd8"
    resource_group = "Packer"
    gallery_name = "Packer_image_gallery"
    image_name = "dlcm-ubuntu-1804"
    image_version = "1.0.2"
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
