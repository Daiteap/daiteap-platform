packer {
  required_plugins {
    openstack = {
      version = ">= 0.0.1"
      source = "github.com/hashicorp/openstack"
    }
  }
}

variable "image_prefix" {
  type    = string
  default = "dlcm-ubuntu-1804"
}

variable "public_key" {
  type = string
}

variable "image_version" {
  type    = string
  default = "1"
}

variable "source_image" {
  type    = string
}

variable "application_credential_id" {
  type    = string
}

variable "application_credential_secret" {
  type    = string
}

variable "identity_endpoint" {
  type    = string
}

variable "floating_ip_network" {
  type    = string
}

variable "private_network" {
  type    = string
}

variable "security_group_name" {
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
    "sudo apt-get install -y aufs-tools ca-certificates curl dbus dnsmasq fail2ban libstrongswan libstrongswan-standard-plugins nfs-common openssl python3 python3-pip resolvconf strongswan strongswan-charon",
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
    "sudo useradd -m -G sudo clouduser",
    "sudo echo 'clouduser ALL=(ALL:ALL) NOPASSWD: ALL' | sudo EDITOR='tee -a' visudo",
    "sudo su - clouduser -c 'id'",
    "sudo su - clouduser -c 'mkdir /home/clouduser/.ssh'",
    "sudo su - clouduser -c 'touch /home/clouduser/.ssh/authorized_keys'",
    "sudo su - clouduser -c \"echo '${var.public_key}' >> /home/clouduser/.ssh/authorized_keys\"",
    "sudo su - clouduser -c 'chmod 600 /home/clouduser/.ssh/authorized_keys'",
    "sudo su - clouduser -c 'chmod 700 /home/clouduser/.ssh'",
  ]
}

source "openstack" "example" {
  application_credential_id     = "${var.application_credential_id}"
  application_credential_secret = "${var.application_credential_secret}"
  identity_endpoint             = "${var.identity_endpoint}"

  source_image = "${var.source_image}"
  flavor       = "111"

  region                   = "f1a"
  availability_zone        = "AZ3"
  ssh_username             = "ubuntu"
  ssh_interface            = "public"
  floating_ip_network      = "${var.floating_ip_network}"
  instance_floating_ip_net = "${var.floating_ip_network}"
  networks = ["${var.private_network}"]
  security_groups = [
    "${var.security_group_name}"
  ]

  image_name   = "${var.image_prefix}-${var.image_version}"
  image_min_disk = 10
  volume_size  = 10

  image_tags = ["daiteap_dlcm_v2"]
}

build {
  sources = ["source.openstack.example"]

  provisioner "shell" {
    environment_vars = [
      "CUSTOM_TEXT=Daiteap",
    ]
    inline = "${var.inline_commands}"
  }
}