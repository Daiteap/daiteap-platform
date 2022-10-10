# Alicloud
resource "alicloud_vpn_gateway" "vpngw_azurerm" {
  name                 = "${var.alicloud_vpc_name}-vgw-azurerm"
  vpc_id               = alicloud_vpc.vpc.id
  bandwidth            = "10"
  enable_ssl           = true
  instance_charge_type = "PostPaid"
  vswitch_id           = alicloud_vswitch.vswitch.id
}

resource "alicloud_vpn_customer_gateway" "cgw_azurerm" {
  name       = "${var.alicloud_vpc_name}-cgw-azurerm"
  ip_address = data.azurerm_public_ip.alicloud.ip_address
}

resource "alicloud_vpn_connection" "vpn_azurerm" {
  name                = "${var.alicloud_vpc_name}-vpn-azurerm"
  vpn_gateway_id      = alicloud_vpn_gateway.vpngw_azurerm.id
  customer_gateway_id = alicloud_vpn_customer_gateway.cgw_azurerm.id
  local_subnet        = [var.alicloud_vswitch_cidr]
  remote_subnet       = [var.azurerm_vpc_cidr]
  effect_immediately  = true
  ike_config {
    ike_auth_alg = "sha1"
    ike_enc_alg  = "aes256"
    ike_version  = "ikev2"
    ike_mode     = "main"
    ike_pfs      = "group2"
    ike_lifetime = 28800
    psk          = random_string.shared_key_azure_alicloud.result
  }
  ipsec_config {
    ipsec_pfs      = "disabled"
    ipsec_enc_alg  = "aes256"
    ipsec_auth_alg = "sha1"
    ipsec_lifetime = 28800
  }
}

resource "alicloud_route_entry" "vpn_azurerm" {
  route_table_id        = alicloud_vpc.vpc.route_table_id
  destination_cidrblock = var.azurerm_vpc_cidr
  nexthop_type          = "VpnGateway"
  nexthop_id            = alicloud_vpn_gateway.vpngw_azurerm.id
}

# -- Azure
resource "azurerm_local_network_gateway" "alicloud_main" {
  name                = "${var.azurerm_prefix}-vpn-alicloud"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  gateway_address     = alicloud_vpn_gateway.vpngw_azurerm.internet_ip
  address_space       = [var.alicloud_vswitch_cidr]

  tags = {
    daiteap-env-id = var.azurerm_environment_id,
    daiteap-username = var.azurerm_daiteap_username,
    daiteap-user-email = var.azurerm_daiteap_user_email,
    daiteap-platform-url = var.azurerm_daiteap_platform_url,
    daiteap-workspace-name = var.azurerm_daiteap_workspace_name
  }
}

resource "azurerm_virtual_network_gateway_connection" "alicloud" {
  name                = "${var.azurerm_prefix}-vpn-alicloud"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name

  type                       = "IPsec"
  virtual_network_gateway_id = azurerm_virtual_network_gateway.vpn_default.id
  local_network_gateway_id   = azurerm_local_network_gateway.alicloud_main.id

  shared_key = random_string.shared_key_azure_alicloud.result

  tags = {
    daiteap-env-id = var.azurerm_environment_id,
    daiteap-username = var.azurerm_daiteap_username,
    daiteap-user-email = var.azurerm_daiteap_user_email,
    daiteap-platform-url = var.azurerm_daiteap_platform_url,
    daiteap-workspace-name = var.azurerm_daiteap_workspace_name
  }
}

data "azurerm_public_ip" "alicloud" {
  name                = azurerm_public_ip.vpn_default.name
  resource_group_name = azurerm_resource_group.main.name
  depends_on          = [azurerm_virtual_network_gateway.vpn_default]

  tags = {
    daiteap-env-id = var.azurerm_environment_id,
    daiteap-username = var.azurerm_daiteap_username,
    daiteap-user-email = var.azurerm_daiteap_user_email,
    daiteap-platform-url = var.azurerm_daiteap_platform_url,
    daiteap-workspace-name = var.azurerm_daiteap_workspace_name
  }
}

resource "random_string" "shared_key_azure_alicloud" {
  length  = 16
  special = false
}
