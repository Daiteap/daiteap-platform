resource "azurerm_subnet" "vpn_gateway" {
  name                 = "GatewaySubnet"
  resource_group_name  = azurerm_resource_group.main.name
  virtual_network_name = azurerm_virtual_network.main.name
  address_prefixes       = [var.azurerm_vpc_gateway_cidr]
}

resource "azurerm_public_ip" "vpn_default" {
  name                = "${var.azurerm_prefix}-vpn"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  allocation_method   = "Dynamic"

  tags = {
    daiteap-env-id = var.azurerm_environment_id,
    daiteap-username = var.azurerm_daiteap_username,
    daiteap-user-email = var.azurerm_daiteap_user_email,
    daiteap-platform-url = var.azurerm_daiteap_platform_url,
    daiteap-workspace-name = var.azurerm_daiteap_workspace_name
  }
}

resource "azurerm_virtual_network_gateway" "vpn_default" {
  name                = "${var.azurerm_prefix}-vpn"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name

  type     = "Vpn"
  vpn_type = "RouteBased"

  active_active = false
  enable_bgp    = false
  sku           = "Basic"

  ip_configuration {
    public_ip_address_id          = azurerm_public_ip.vpn_default.id
    private_ip_address_allocation = "Dynamic"
    subnet_id                     = azurerm_subnet.vpn_gateway.id
  }

  timeouts {
    create = "300m"
    update = "300m"
    read   = "15m"
    delete = "300m"
  }

  tags = {
    daiteap-env-id = var.azurerm_environment_id,
    daiteap-username = var.azurerm_daiteap_username,
    daiteap-user-email = var.azurerm_daiteap_user_email,
    daiteap-platform-url = var.azurerm_daiteap_platform_url,
    daiteap-workspace-name = var.azurerm_daiteap_workspace_name
  }
}
