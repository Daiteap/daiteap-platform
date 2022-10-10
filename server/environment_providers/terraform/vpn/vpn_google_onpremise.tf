variable "google_onpremise_shared_secret" {
  default = "secret"
}

variable "google_onpremise_network_cidr" {
  default = "10.0.0.0/16"
}

variable "google_onpremise_vpn_gateway_internet_ip" {
  default = "1.1.1.1"
}

# -- Google
# Create a static IP in GCE
resource "google_compute_address" "onpremise" {
  name = "${var.google_vpc_name}-vpn-onpremise"

  description = var.google_environment_id
}

# Create the VPN
resource "google_compute_vpn_gateway" "onpremise" {
  name    = "${var.google_vpc_name}-vpn-onpremise"
  network = google_compute_network.vpc_network.self_link

  description = var.google_environment_id
}

resource "google_compute_forwarding_rule" "onpremise_fr_esp" {
  name        = "${var.google_vpc_name}-onpremise-fr-esp"
  ip_protocol = "ESP"
  ip_address  = google_compute_address.onpremise.address
  target      = google_compute_vpn_gateway.onpremise.self_link
}

resource "google_compute_forwarding_rule" "onpremise_fr_udp500" {
  name        = "${var.google_vpc_name}-onpremise-fr-udp500"
  ip_protocol = "UDP"
  port_range  = "500"
  ip_address  = google_compute_address.onpremise.address
  target      = google_compute_vpn_gateway.onpremise.self_link

  description = var.google_environment_id
}

resource "google_compute_forwarding_rule" "onpremise_fr_udp4500" {
  name        = "${var.google_vpc_name}-onpremise-fr-udp4500"
  ip_protocol = "UDP"
  port_range  = "4500"
  ip_address  = google_compute_address.onpremise.address
  target      = google_compute_vpn_gateway.onpremise.self_link

  description = var.google_environment_id
}

# Configure the tunnels
resource "google_compute_vpn_tunnel" "onpremise_tunnel1" {
  name          = "${var.google_vpc_name}-onpremise-tunnel1"
  peer_ip       = var.google_onpremise_vpn_gateway_internet_ip
  shared_secret = var.google_onpremise_shared_secret

  target_vpn_gateway      = google_compute_vpn_gateway.onpremise.self_link
  remote_traffic_selector = [var.google_onpremise_network_cidr]
  ike_version             = "2"
  local_traffic_selector  = toset([var.google_vpc_cidr])

  depends_on = [
    google_compute_forwarding_rule.onpremise_fr_esp,
    google_compute_forwarding_rule.onpremise_fr_udp500,
    google_compute_forwarding_rule.onpremise_fr_udp4500,
  ]

  description = var.google_environment_id
}

resource "google_compute_route" "onpremise_route_to_vpn-tunnel-1" {
  name       = "${var.google_vpc_name}-onpremise-tunnel-1-route1"
  network    = google_compute_network.vpc_network.name
  dest_range = var.google_onpremise_network_cidr
  priority   = 1000

  next_hop_vpn_tunnel = google_compute_vpn_tunnel.onpremise_tunnel1.self_link

  description = var.google_environment_id
}
