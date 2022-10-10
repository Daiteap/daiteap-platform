# -- Azure
resource "azurerm_local_network_gateway" "google_main" {
  name                = "${var.azurerm_prefix}-vpn-google"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  gateway_address     = google_compute_address.google_vpn_static_ip.address
  address_space       = [var.google_vpc_cidr]

  tags = {
    daiteap-env-id = var.azurerm_environment_id,
    daiteap-username = var.azurerm_daiteap_username,
    daiteap-user-email = var.azurerm_daiteap_user_email,
    daiteap-platform-url = var.azurerm_daiteap_platform_url,
    daiteap-workspace-name = var.azurerm_daiteap_workspace_name
  }
}

resource "azurerm_virtual_network_gateway_connection" "google" {
  name                = "${var.azurerm_prefix}-vpn-google"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name

  type                       = "IPsec"
  virtual_network_gateway_id = azurerm_virtual_network_gateway.vpn_default.id
  local_network_gateway_id   = azurerm_local_network_gateway.google_main.id

  shared_key = random_string.shared_key_google_azure.result

  tags = {
    daiteap-env-id = var.azurerm_environment_id,
    daiteap-username = var.azurerm_daiteap_username,
    daiteap-user-email = var.azurerm_daiteap_user_email,
    daiteap-platform-url = var.azurerm_daiteap_platform_url,
    daiteap-workspace-name = var.azurerm_daiteap_workspace_name
  }
}

data "azurerm_public_ip" "google" {
  name                = azurerm_public_ip.vpn_default.name
  resource_group_name = azurerm_resource_group.main.name
  depends_on          = [azurerm_virtual_network_gateway.vpn_default]

  // tags = {
  //   daiteap-env-id = var.azurerm_environment_id,
  //   daiteap-username = var.azurerm_daiteap_username,
  //   daiteap-user-email = var.azurerm_daiteap_user_email,
  //   daiteap-platform-url = var.azurerm_daiteap_platform_url,
  //   daiteap-workspace-name = var.azurerm_daiteap_workspace_name
  // }
}

resource "random_string" "shared_key_google_azure" {
  length  = 16
  special = false
}


# -- Google
# Create a static IP in GCE
resource "google_compute_address" "google_vpn_static_ip" {
  name = "${var.google_vpc_name}-vpn-azure"

  description = var.google_environment_id
}

# Create the VPN
resource "google_compute_vpn_gateway" "vpn_azure" {
  name    = "${var.google_vpc_name}-vpn-azure"
  network = google_compute_network.vpc_network.self_link

  description = var.google_environment_id
}

resource "google_compute_forwarding_rule" "azure_fr_esp" {
  name        = "${var.google_vpc_name}-azure-fr-esp"
  ip_protocol = "ESP"
  ip_address  = google_compute_address.google_vpn_static_ip.address
  target      = google_compute_vpn_gateway.vpn_azure.self_link

  description = var.google_environment_id
}

resource "google_compute_forwarding_rule" "azure_fr_udp500" {
  name        = "${var.google_vpc_name}-azure-fr-udp500"
  ip_protocol = "UDP"
  port_range  = "500"
  ip_address  = google_compute_address.google_vpn_static_ip.address
  target      = google_compute_vpn_gateway.vpn_azure.self_link

  description = var.google_environment_id
}

resource "google_compute_forwarding_rule" "azure_fr_udp4500" {
  name        = "${var.google_vpc_name}-azure-fr-udp4500"
  ip_protocol = "UDP"
  port_range  = "4500"
  ip_address  = google_compute_address.google_vpn_static_ip.address
  target      = google_compute_vpn_gateway.vpn_azure.self_link

  description = var.google_environment_id
}

# Configure the tunnels
resource "google_compute_vpn_tunnel" "azure_tunnel1" {
  name          = "${var.google_vpc_name}-azure-tunnel1"
  peer_ip       = data.azurerm_public_ip.google.ip_address
  shared_secret = random_string.shared_key_google_azure.result

  target_vpn_gateway     = google_compute_vpn_gateway.vpn_azure.self_link
  remote_traffic_selector = [var.azurerm_vpc_cidr]
  ike_version            = "2"
  local_traffic_selector = toset([var.google_vpc_cidr])

  depends_on = [
    google_compute_forwarding_rule.azure_fr_esp,
    google_compute_forwarding_rule.azure_fr_udp500,
    google_compute_forwarding_rule.azure_fr_udp4500,
  ]

  description = var.google_environment_id
}

resource "google_compute_route" "azure_route_to_vpn-tunnel-1" {
  name       = "${var.google_vpc_name}-azure-tunnel-1-route1"
  network    = google_compute_network.vpc_network.name
  dest_range = var.azurerm_vpc_cidr
  priority   = 1000

  next_hop_vpn_tunnel = google_compute_vpn_tunnel.azure_tunnel1.self_link

  description = var.google_environment_id
}
