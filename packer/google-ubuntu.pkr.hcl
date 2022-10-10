packer {
  required_plugins {
    googlecompute = {
      version = ">= 0.0.1"
      source = "github.com/hashicorp/googlecompute"
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

source "googlecompute" "basic-example" {
  project_id = "daiteapdevplayground"
  zone = "europe-west3-a"
  // source_image = "ubuntu-1804-bionic-*"
  source_image_family = "ubuntu-1804-lts"
  ssh_username = "ubuntu"
  image_name = "${var.image_prefix}-${var.image_version}"
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