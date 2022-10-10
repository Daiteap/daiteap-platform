variable "azure_onpremise_shared_secret" {
  default = "secret"
}

variable "azure_onpremise_network_cidr" {
  default = "10.0.0.0/16"
}

variable "azure_onpremise_vpn_gateway_internet_ip" {
  default = "1.1.1.1"
}

# -- Azure
resource "azurerm_local_network_gateway" "onpremise_main" {
  name                = "${var.azurerm_prefix}-vpn-onpremise"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  gateway_address     = var.azure_onpremise_vpn_gateway_internet_ip
  address_space       = [var.azure_onpremise_network_cidr]

  tags = {
    daiteap-env-id = var.azurerm_environment_id,
    daiteap-username = var.azurerm_daiteap_username,
    daiteap-user-email = var.azurerm_daiteap_user_email,
    daiteap-platform-url = var.azurerm_daiteap_platform_url,
    daiteap-workspace-name = var.azurerm_daiteap_workspace_name
  }
}

resource "azurerm_virtual_network_gateway_connection" "onpremise" {
  name                = "${var.azurerm_prefix}-vpn-onpremise"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name

  type                       = "IPsec"
  virtual_network_gateway_id = azurerm_virtual_network_gateway.vpn_default.id
  local_network_gateway_id   = azurerm_local_network_gateway.onpremise_main.id

  shared_key = var.azure_onpremise_shared_secret

  tags = {
    daiteap-env-id = var.azurerm_environment_id,
    daiteap-username = var.azurerm_daiteap_username,
    daiteap-user-email = var.azurerm_daiteap_user_email,
    daiteap-platform-url = var.azurerm_daiteap_platform_url,
    daiteap-workspace-name = var.azurerm_daiteap_workspace_name
  }
}

data "azurerm_public_ip" "onpremise" {
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