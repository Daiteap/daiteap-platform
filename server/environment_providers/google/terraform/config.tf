variable "google_credentials_file" {
  description = "Path to credentials file"
  default     = "/var/credentials/google.json"
}

variable "google_public_key_name" {
  description = "SSH key name in your Google account for Google instances."
  default     = "id_rsa"
}

variable "google_public_key_path" {
  description = "Path to the private key specified by google_public_key_name."
  default     = "/var/.ssh/id_rsa.pub"
}

variable "google_private_key_path" {
  description = "Path to the private key specified by google_public_key_name."
  default     = "/var/.ssh/id_rsa"
}

variable "google_internal_dns_zone" {}

variable "google_vpc_name" {
  default = "clustername"
}

variable "google_user" {
  default = "ubuntu"
}

variable "google_region" {
  description = "The region of Google."
  default     = ""
}

variable "google_project" {
  default = ""
}

variable "google_vpc_cidr" {
  default = "10.10.0.0/16"
}

variable "google_environment_id" {
  default = "test"
}

variable "google_daiteap_username" {
  default = "test"
}

variable "google_daiteap_user_email" {
  default = "test"
}

variable "google_daiteap_platform_url" {
  default = "test"
}

variable "google_daiteap_workspace_name" {
  default = "test"
}

variable "google_instances" {
  type = list(
    object({
      instance_name   = string,
      instance_image   = string,
      instance_type    = string,
      instance_storage = string,
      zone             = string
  }))
}


provider "google" {
  credentials = var.google_credentials_file
  project     = var.google_project
  region      = var.google_region
}

resource "google_compute_firewall" "default" {
  name    = var.google_vpc_name
  network = google_compute_network.vpc_network.name

  allow {
    protocol = "all"
  }

  source_ranges = ["0.0.0.0/0"]

  description = var.google_environment_id
}

resource "google_compute_network" "vpc_network" {
  name                    = var.google_vpc_name
  auto_create_subnetworks = "false"

  description = var.google_environment_id
}

resource "google_compute_subnetwork" "vpc_subnetwork" {
  name          = var.google_vpc_name
  network       = google_compute_network.vpc_network.name
  ip_cidr_range = var.google_vpc_cidr

  description = var.google_environment_id
}

resource "google_compute_address" "static" {
  name     = each.value.instance_name
  for_each = { for node in var.google_instances : node.instance_name => node }

  description = var.google_environment_id
}

resource "google_dns_managed_zone" "private-zone" {
  name     = "${var.google_vpc_name}-private-zone"
  dns_name = var.google_internal_dns_zone

  visibility = "private"

  private_visibility_config {
    networks {
      network_url = google_compute_network.vpc_network.self_link
    }
  }

  description = var.google_environment_id
  labels = {
    daiteap-env-id = var.google_environment_id,
    daiteap-username = var.google_daiteap_username,
    daiteap-user-email = var.google_daiteap_user_email,
    daiteap-platform-url = var.google_daiteap_platform_url,
    daiteap-workspace-name = var.google_daiteap_workspace_name
  }
}

resource "google_dns_record_set" "google_nodes_dns_records" {
  name     = "${each.value.name}.${google_dns_managed_zone.private-zone.dns_name}"
  type     = "A"
  ttl      = 300
  for_each = { for node in google_compute_instance.google_nodes : node.name => node }

  managed_zone = google_dns_managed_zone.private-zone.name

  rrdatas = [each.value.network_interface[0].network_ip]
}

resource "google_compute_instance" "google_nodes" {
  name           = each.value.instance_name
  machine_type   = each.value.instance_type
  for_each       = { for node in var.google_instances : node.instance_name => node }
  can_ip_forward = true
  zone           = each.value.zone

  tags = [var.google_vpc_name]

  service_account {
    scopes = ["cloud-platform"]
  }

  connection {
    user        = var.google_user
    host        = self.network_interface.0.access_config.0.nat_ip
    private_key = file(var.google_private_key_path)
  }

  boot_disk {
    initialize_params {
      image = each.value.instance_image
      size  = each.value.instance_storage
    }
  }

  network_interface {
    access_config {
      nat_ip = google_compute_address.static[each.key].address
    }
    subnetwork = google_compute_subnetwork.vpc_subnetwork.name
  }

  metadata = {
    ssh-keys = "${var.google_user}:${file(var.google_public_key_path)}"
  }

  provisioner "remote-exec" {
    inline = [
      "ls"
    ]
  }

  labels = {
    daiteap-env-id = var.google_environment_id,
    daiteap-username = var.google_daiteap_username,
    daiteap-user-email = var.google_daiteap_user_email,
    daiteap-platform-url = var.google_daiteap_platform_url,
    daiteap-workspace-name = var.google_daiteap_workspace_name
  }
  description = var.google_environment_id
}
