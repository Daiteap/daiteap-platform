
# - Azure

resource "azurerm_local_network_gateway" "aws_main1" {
  name                = "${var.azurerm_prefix}-vpn-aws1"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  gateway_address     = aws_vpn_connection.azure.tunnel1_address
  address_space       = [var.aws_vpc_cidr]

  tags = {
    daiteap-env-id = var.azurerm_environment_id,
    daiteap-username = var.azurerm_daiteap_username,
    daiteap-user-email = var.azurerm_daiteap_user_email,
    daiteap-platform-url = var.azurerm_daiteap_platform_url,
    daiteap-workspace-name = var.azurerm_daiteap_workspace_name
  }
}

resource "azurerm_local_network_gateway" "aws_main2" {
  name                = "${var.azurerm_prefix}-vpn-aws2"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  gateway_address     = aws_vpn_connection.azure.tunnel2_address
  address_space       = [var.aws_vpc_cidr]

  tags = {
    daiteap-env-id = var.azurerm_environment_id,
    daiteap-username = var.azurerm_daiteap_username,
    daiteap-user-email = var.azurerm_daiteap_user_email,
    daiteap-platform-url = var.azurerm_daiteap_platform_url,
    daiteap-workspace-name = var.azurerm_daiteap_workspace_name
  }
}

resource "azurerm_virtual_network_gateway_connection" "aws1" {
  name                = "${var.azurerm_prefix}-vpn-aws1"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name

  type                       = "IPsec"
  virtual_network_gateway_id = azurerm_virtual_network_gateway.vpn_default.id
  local_network_gateway_id   = azurerm_local_network_gateway.aws_main1.id

  shared_key = aws_vpn_connection.azure.tunnel1_preshared_key

  tags = {
    daiteap-env-id = var.azurerm_environment_id,
    daiteap-username = var.azurerm_daiteap_username,
    daiteap-user-email = var.azurerm_daiteap_user_email,
    daiteap-platform-url = var.azurerm_daiteap_platform_url,
    daiteap-workspace-name = var.azurerm_daiteap_workspace_name
  }
}

resource "azurerm_virtual_network_gateway_connection" "aws2" {
  name                = "${var.azurerm_prefix}-vpn-aws2"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name

  type                       = "IPsec"
  virtual_network_gateway_id = azurerm_virtual_network_gateway.vpn_default.id
  local_network_gateway_id   = azurerm_local_network_gateway.aws_main2.id

  shared_key = aws_vpn_connection.azure.tunnel2_preshared_key

  tags = {
    daiteap-env-id = var.azurerm_environment_id,
    daiteap-username = var.azurerm_daiteap_username,
    daiteap-user-email = var.azurerm_daiteap_user_email,
    daiteap-platform-url = var.azurerm_daiteap_platform_url,
    daiteap-workspace-name = var.azurerm_daiteap_workspace_name
  }
}

data "azurerm_public_ip" "vpn_aws" {
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

# - AWS
# Create a "Customer Gateway" in AWS
resource "aws_customer_gateway" "main" {
  bgp_asn    = 65000
  ip_address = data.azurerm_public_ip.vpn_aws.ip_address
  type       = "ipsec.1"

  tags = {
    Name = "${var.aws_vpc_name}-vpn-azure"
    daiteap-env-id = var.aws_environment_id,
    daiteap-username = var.aws_daiteap_username,
    daiteap-user-email = var.aws_daiteap_user_email,
    daiteap-platform-url = var.aws_daiteap_platform_url,
    daiteap-workspace-name = var.aws_daiteap_workspace_name
  }
}


# Route propagation
resource "aws_route" "azure" {
  route_table_id         = aws_vpc.default.main_route_table_id
  destination_cidr_block = var.azurerm_vpc_cidr
  gateway_id             = aws_vpn_gateway.default.id
}

# Route propagation
resource "aws_vpn_gateway_route_propagation" "azure" {
  vpn_gateway_id = aws_vpn_gateway.default.id
  route_table_id = aws_vpc.default.main_route_table_id
}

# Create the "VPN Connection"
resource "aws_vpn_connection" "azure" {
  vpn_gateway_id      = aws_vpn_gateway.default.id
  customer_gateway_id = aws_customer_gateway.main.id
  type                = "ipsec.1"
  static_routes_only  = true

  tags = {
    Name = var.aws_vpc_name
    daiteap-env-id = var.aws_environment_id,
    daiteap-username = var.aws_daiteap_username,
    daiteap-user-email = var.aws_daiteap_user_email,
    daiteap-platform-url = var.aws_daiteap_platform_url,
    daiteap-workspace-name = var.aws_daiteap_workspace_name
  }
}

# Create the "VPN Connection"
resource "aws_vpn_connection_route" "azure" {
  destination_cidr_block = var.azurerm_vpc_cidr
  vpn_connection_id      = aws_vpn_connection.azure.id
}
