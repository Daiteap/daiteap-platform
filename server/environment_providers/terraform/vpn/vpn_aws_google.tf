# Create a "Customer Gateway" in AWS
resource "aws_customer_gateway" "google_main" {
  bgp_asn    = 65000
  ip_address = google_compute_address.aws_vpn_static_ip.address
  type       = "ipsec.1"

  tags = {
    Name           = var.aws_vpc_name
    daiteap-env-id = var.aws_environment_id,
    daiteap-username = var.aws_daiteap_username,
    daiteap-user-email = var.aws_daiteap_user_email,
    daiteap-platform-url = var.aws_daiteap_platform_url,
    daiteap-workspace-name = var.aws_daiteap_workspace_name
  }
}


# Route propagation
resource "aws_route" "google" {
  route_table_id         = aws_vpc.default.main_route_table_id
  destination_cidr_block = var.google_vpc_cidr
  gateway_id             = aws_vpn_gateway.default.id
}

# Route propagation
resource "aws_vpn_gateway_route_propagation" "google" {
  vpn_gateway_id = aws_vpn_gateway.default.id
  route_table_id = aws_vpc.default.main_route_table_id
}

# Create the "VPN Connection"
resource "aws_vpn_connection" "google" {
  vpn_gateway_id      = aws_vpn_gateway.default.id
  customer_gateway_id = aws_customer_gateway.google_main.id
  type                = "ipsec.1"
  static_routes_only  = true

  tags = {
    Name           = var.aws_vpc_name
    daiteap-env-id = var.aws_environment_id,
    daiteap-username = var.aws_daiteap_username,
    daiteap-user-email = var.aws_daiteap_user_email,
    daiteap-platform-url = var.aws_daiteap_platform_url,
    daiteap-workspace-name = var.aws_daiteap_workspace_name
  }
}

# Create the "VPN Connection"
resource "aws_vpn_connection_route" "google" {
  destination_cidr_block = var.google_vpc_cidr
  vpn_connection_id      = aws_vpn_connection.google.id

}

# Create a static IP in GCE
resource "google_compute_address" "aws_vpn_static_ip" {
  name = var.google_vpc_name

  description = var.google_environment_id
}

# Create the VPN
resource "google_compute_vpn_gateway" "vpn_aws" {
  name    = "${var.aws_vpc_name}-vpn-aws"
  network = google_compute_network.vpc_network.self_link

  description = var.google_environment_id
}

resource "google_compute_forwarding_rule" "aws_fr_esp" {
  name        = "${var.aws_vpc_name}-google-fr-esp"
  ip_protocol = "ESP"
  ip_address  = google_compute_address.aws_vpn_static_ip.address
  target      = google_compute_vpn_gateway.vpn_aws.self_link

  description = var.google_environment_id
}

resource "google_compute_forwarding_rule" "aws_fr_udp500" {
  name        = "${var.aws_vpc_name}-google-fr-udp500"
  ip_protocol = "UDP"
  port_range  = "500"
  ip_address  = google_compute_address.aws_vpn_static_ip.address
  target      = google_compute_vpn_gateway.vpn_aws.self_link

  description = var.google_environment_id
}

resource "google_compute_forwarding_rule" "aws_fr_udp4500" {
  name        = "${var.aws_vpc_name}-google-fr-udp4500"
  ip_protocol = "UDP"
  port_range  = "4500"
  ip_address  = google_compute_address.aws_vpn_static_ip.address
  target      = google_compute_vpn_gateway.vpn_aws.self_link

  description = var.google_environment_id
}

# Configure the tunnels
resource "google_compute_vpn_tunnel" "aws_tunnel1" {
  name          = "${var.aws_vpc_name}-aws-tunnel1"
  peer_ip       = aws_vpn_connection.google.tunnel1_address
  shared_secret = aws_vpn_connection.google.tunnel1_preshared_key

  target_vpn_gateway      = google_compute_vpn_gateway.vpn_aws.self_link
  remote_traffic_selector = [var.aws_vpc_cidr]
  ike_version             = "1"
  local_traffic_selector  = toset([var.google_vpc_cidr])

  depends_on = [
    google_compute_forwarding_rule.aws_fr_esp,
    google_compute_forwarding_rule.aws_fr_udp500,
    google_compute_forwarding_rule.aws_fr_udp4500,
  ]

  description = var.google_environment_id
}

resource "google_compute_vpn_tunnel" "aws_tunnel2" {
  name          = "${var.aws_vpc_name}-aws-tunnel2"
  peer_ip       = aws_vpn_connection.google.tunnel2_address
  shared_secret = aws_vpn_connection.google.tunnel2_preshared_key

  target_vpn_gateway      = google_compute_vpn_gateway.vpn_aws.self_link
  remote_traffic_selector = [var.aws_vpc_cidr]
  ike_version             = "1"
  local_traffic_selector  = toset([var.google_vpc_cidr])

  depends_on = [
    google_compute_forwarding_rule.aws_fr_esp,
    google_compute_forwarding_rule.aws_fr_udp500,
    google_compute_forwarding_rule.aws_fr_udp4500,
  ]

  description = var.google_environment_id
}

resource "google_compute_route" "google_route_to_vpn-tunnel-1" {
  name       = "${var.aws_vpc_name}-google-tunnel-1-route1"
  network    = google_compute_network.vpc_network.name
  dest_range = aws_vpc.default.cidr_block
  priority   = 1000

  next_hop_vpn_tunnel = google_compute_vpn_tunnel.aws_tunnel1.self_link

  description = var.google_environment_id
}

resource "google_compute_route" "google_route_to_vpn-tunnel-2" {
  name       = "${var.aws_vpc_name}-tunnel-2-route1"
  network    = google_compute_network.vpc_network.name
  dest_range = aws_vpc.default.cidr_block
  priority   = 1000

  next_hop_vpn_tunnel = google_compute_vpn_tunnel.aws_tunnel2.self_link

  description = var.google_environment_id
}
