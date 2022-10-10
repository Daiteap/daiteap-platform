# -- Google
# Create a static IP in GCE
resource "google_compute_address" "vpn_alicloud" {
  name = "${var.google_vpc_name}-vpn-alicloud"

  description = var.google_environment_id
}

# Create the VPN
resource "google_compute_vpn_gateway" "vpn_alicloud" {
  name    = "${var.google_vpc_name}-vpn-alicloud"
  network = google_compute_network.vpc_network.self_link

  description = var.google_environment_id
}

resource "google_compute_forwarding_rule" "alicloud_fr_esp" {
  name        = "${var.google_vpc_name}-alicloud-fr-esp"
  ip_protocol = "ESP"
  ip_address  = google_compute_address.vpn_alicloud.address
  target      = google_compute_vpn_gateway.vpn_alicloud.self_link
}

resource "google_compute_forwarding_rule" "alicloud_fr_udp500" {
  name        = "${var.google_vpc_name}-alicloud-fr-udp500"
  ip_protocol = "UDP"
  port_range  = "500"
  ip_address  = google_compute_address.vpn_alicloud.address
  target      = google_compute_vpn_gateway.vpn_alicloud.self_link

  description = var.google_environment_id
}

resource "google_compute_forwarding_rule" "alicloud_fr_udp4500" {
  name        = "${var.google_vpc_name}-alicloud-fr-udp4500"
  ip_protocol = "UDP"
  port_range  = "4500"
  ip_address  = google_compute_address.vpn_alicloud.address
  target      = google_compute_vpn_gateway.vpn_alicloud.self_link

  description = var.google_environment_id
}

# Configure the tunnels
resource "google_compute_vpn_tunnel" "alicloud_tunnel1" {
  name          = "${var.google_vpc_name}-alicloud-tunnel1"
  peer_ip       = alicloud_vpn_gateway.vpngw_google.internet_ip
  shared_secret = random_string.shared_key_google_alicloud.result

  target_vpn_gateway      = google_compute_vpn_gateway.vpn_alicloud.self_link
  remote_traffic_selector = [var.alicloud_vswitch_cidr]
  ike_version             = "2"
  local_traffic_selector  = toset([var.google_vpc_cidr])

  depends_on = [
    google_compute_forwarding_rule.alicloud_fr_esp,
    google_compute_forwarding_rule.alicloud_fr_udp500,
    google_compute_forwarding_rule.alicloud_fr_udp4500,
  ]

  description = var.google_environment_id
}

resource "google_compute_route" "alicloud_route_to_vpn-tunnel-1" {
  name       = "${var.google_vpc_name}-alicloud-tunnel-1-route1"
  network    = google_compute_network.vpc_network.name
  dest_range = var.alicloud_vswitch_cidr
  priority   = 1000

  next_hop_vpn_tunnel = google_compute_vpn_tunnel.alicloud_tunnel1.self_link

  description = var.google_environment_id
}

# Alicloud
resource "alicloud_vpn_gateway" "vpngw_google" {
  name                 = "${var.alicloud_vpc_name}-vgw-google"
  vpc_id               = alicloud_vpc.vpc.id
  bandwidth            = "10"
  enable_ssl           = true
  instance_charge_type = "PostPaid"
  vswitch_id           = alicloud_vswitch.vswitch.id
}

resource "alicloud_vpn_customer_gateway" "cgw_google" {
  name       = "${var.alicloud_vpc_name}-cgw-google"
  ip_address = google_compute_address.vpn_alicloud.address
}

resource "alicloud_vpn_connection" "vpn_google" {
  name                = "${var.alicloud_vpc_name}-vpn-google"
  vpn_gateway_id      = alicloud_vpn_gateway.vpngw_google.id
  customer_gateway_id = alicloud_vpn_customer_gateway.cgw_google.id
  local_subnet        = [var.alicloud_vswitch_cidr]
  remote_subnet       = [var.google_vpc_cidr]
  effect_immediately  = true
  ike_config {
    ike_auth_alg = "sha1"
    ike_enc_alg  = "aes256"
    ike_version  = "ikev2"
    ike_mode     = "main"
    ike_pfs      = "group14"
    ike_lifetime = 28800
    psk          = random_string.shared_key_google_alicloud.result
  }
  ipsec_config {
    ipsec_pfs      = "group14"
    ipsec_enc_alg  = "aes256"
    ipsec_auth_alg = "sha1"
    ipsec_lifetime = 28800
  }
}

resource "alicloud_route_entry" "vpn_google" {
  route_table_id        = alicloud_vpc.vpc.route_table_id
  destination_cidrblock = var.google_vpc_cidr
  nexthop_type          = "VpnGateway"
  nexthop_id            = alicloud_vpn_gateway.vpngw_google.id
}

resource "random_string" "shared_key_google_alicloud" {
  length  = 16
  special = false
}
