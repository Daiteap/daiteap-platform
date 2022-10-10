terraform {
required_version = ">= 0.14.0"
  required_providers {
    openstack = {
      source  = "terraform-provider-openstack/openstack"
      version = "~> 1.43.0"
    }
  }
}

variable "openstack_application_credential_id" {
  description = "ID of application credentials used for authentication."
  default     = "1111"
}

variable "openstack_application_credential_secret" {
  description = "Secret of application credentials used for authentication."
  default     = "secret"
}

variable "openstack_user" {
  default = "ubuntu"
}

variable "openstack_public_key_name" {
  description = "SSH key name in your Openstack account for Openstack instances."
  default     = "id_rsa"
}

variable "openstack_public_key_path" {
  description = "Path to the private key specified by openstack_public_key_name."
  default     = "/var/.ssh/id_rsa.pub"
}

variable "openstack_private_key_path" {
  description = "Path to the private key specified by openstack_public_key_name."
  default     = "/var/.ssh/id_rsa"
}

variable "openstack_auth_url" {
  description = "Openstack url to authenticate to."
  default     = "http://0.0.0.0/identity"
}

variable "openstack_region" {
  description = "The region of Openstack."
  default     = "RegionOne"
}

variable "openstack_environment_name" {
  default = "clustername"
}

variable "openstack_environment_id" {
  default = "test"
}

variable "openstack_daiteap_username" {
  default = "test"
}

variable "openstack_daiteap_user_email" {
  default = "test"
}

variable "openstack_daiteap_platform_url" {
  default = "test"
}

variable "openstack_daiteap_workspace_name" {
  default = "test"
}

variable "openstack_vpc_cidr" {
  default = "10.0.0.0/16"
}

variable "openstack_instances" {
  type = list(
    object({
      instance_name = string,
      instance_image = string,
      instance_type  = string,
      instance_storage  = string,
      zone           = string
  }))
}

variable "openstack_external_network_id" {
  description = "Openstack external network ID"
  default     = "1111"
}

provider "openstack" {
  application_credential_id     = var.openstack_application_credential_id
  application_credential_secret = var.openstack_application_credential_secret
  auth_url    = var.openstack_auth_url
  region      = var.openstack_region
  insecure    = true
}

data "openstack_networking_network_v2" "ext_network" {
  network_id = var.openstack_external_network_id
}

resource "openstack_networking_router_v2" "router" {
  name                = var.openstack_environment_name
  admin_state_up      = true
  external_network_id = data.openstack_networking_network_v2.ext_network.id
}

resource "openstack_networking_network_v2" "env_network" {
  name           = var.openstack_environment_name
  admin_state_up = "true"
}

resource "openstack_networking_subnet_v2" "env_subnet" {
  name       = var.openstack_environment_name
  network_id = "${openstack_networking_network_v2.env_network.id}"
  cidr       = var.openstack_vpc_cidr
  ip_version = 4
}

resource "openstack_networking_router_interface_v2" "router_interface" {
  router_id = "${openstack_networking_router_v2.router.id}"
  subnet_id = "${openstack_networking_subnet_v2.env_subnet.id}"
}

resource "openstack_compute_secgroup_v2" "env_secgroup" {
  name        = var.openstack_environment_name
  description = "a security group"

  rule {
    from_port   = 22
    to_port     = 22
    ip_protocol = "tcp"
    cidr        = "0.0.0.0/0"
  }

  rule {
    from_port   = 6443
    to_port     = 6443
    ip_protocol = "tcp"
    cidr        = "0.0.0.0/0"
  }

  rule {
    from_port   = 30000
    to_port     = 32768
    ip_protocol = "tcp"
    cidr        = "0.0.0.0/0"
  }

  rule {
    from_port   = 1
    to_port     = 65535
    ip_protocol = "tcp"
    self        = true
  }

  rule {
    from_port   = 1
    to_port     = 65535
    ip_protocol = "udp"
    self        = true
  }
}

resource "openstack_networking_floatingip_v2" "float_ip" {
  pool  = data.openstack_networking_network_v2.ext_network.name
}

resource "openstack_compute_keypair_v2" "keypair" {
  name       = var.openstack_environment_name
  public_key = file(var.openstack_public_key_path)
}

resource "openstack_compute_instance_v2" "openstack_nodes" {
  for_each          = {for node in var.openstack_instances: node.instance_name => node}
  name              = each.value.instance_name
  flavor_id         = each.value.instance_type
  key_pair          = var.openstack_environment_name
  security_groups   = ["${openstack_compute_secgroup_v2.env_secgroup.name}"]
  availability_zone = each.value.zone

  image_id        = each.value.instance_image

  // user_data = file("../../../../environment_providers/openstack/terraform/openstack-init-script.sh")

  metadata = {
    daiteap-env-id = var.openstack_environment_id,
    daiteap-username = var.openstack_daiteap_username,
    daiteap-user-email = var.openstack_daiteap_user_email,
    daiteap-platform-url = var.openstack_daiteap_platform_url,
    daiteap-workspace-name = var.openstack_daiteap_workspace_name
  }

  network {
    uuid = "${openstack_networking_subnet_v2.env_subnet.network_id}"
  }
}

resource "openstack_compute_floatingip_associate_v2" "associate_floating_ip" {
  floating_ip = openstack_networking_floatingip_v2.float_ip.address
  instance_id = openstack_compute_instance_v2.openstack_nodes[var.openstack_instances[0].instance_name].id
}
