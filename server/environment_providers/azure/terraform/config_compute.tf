provider "azurerm" {
  features {
    resource_group {
      prevent_deletion_if_contains_resources = false
    }
  }

  skip_provider_registration = "true"

  subscription_id = var.azurerm_subscription_id
  client_id       = var.azurerm_client_id
  client_secret   = var.azurerm_client_secret
  tenant_id       = var.azurerm_tenant_id
}

variable "azurerm_internal_dns_zone" {}

variable "azurerm_subscription_id" {
  default = ""
}

variable "azurerm_vpc_cidr" {
  default = "10.30.0.0/16"
}

variable "azurerm_vpc_subnet_cidr" {
  default = "10.30.2.0/24"
}

variable "azurerm_vpc_gateway_cidr" {
  default = "10.30.1.0/16"
}

variable "azurerm_client_id" {
  default = ""
}

variable "azurerm_client_secret" {
  default = ""
}

variable "azurerm_tenant_id" {
  default = ""
}

variable "azurerm_environment_id" {
  default = "test"
}

variable "azurerm_daiteap_username" {
  default = "test"
}

variable "azurerm_daiteap_user_email" {
  default = "test"
}

variable "azurerm_daiteap_platform_url" {
  default = "test"
}

variable "azurerm_daiteap_workspace_name" {
  default = "test"
}

variable "azurerm_prefix" {
  default = "clusternm15"
}

variable "azure_user" {
  default = "clouduser"
}

variable "azurerm_location" {
  default = "Germany West Central"
}

variable "azure_instances" {
  type = list(
    object({
      instance_name    = string,
      image_publisher = string,
      image_offer = string,
      image_sku = string,
      image_version = string,
      instance_storage = string,
      instance_type    = string
  }))
}

resource "azurerm_resource_group" "main" {
  name     = var.azurerm_prefix
  location = var.azurerm_location

  tags = {
    daiteap-env-id = var.azurerm_environment_id,
    daiteap-username = var.azurerm_daiteap_username,
    daiteap-user-email = var.azurerm_daiteap_user_email,
    daiteap-platform-url = var.azurerm_daiteap_platform_url,
    daiteap-workspace-name = var.azurerm_daiteap_workspace_name
  }
}

resource "azurerm_virtual_network" "main" {
  name                = var.azurerm_prefix
  address_space       = [var.azurerm_vpc_cidr]
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name

  tags = {
    daiteap-env-id = var.azurerm_environment_id,
    daiteap-username = var.azurerm_daiteap_username,
    daiteap-user-email = var.azurerm_daiteap_user_email,
    daiteap-platform-url = var.azurerm_daiteap_platform_url,
    daiteap-workspace-name = var.azurerm_daiteap_workspace_name
  }
}

resource "azurerm_subnet" "internal" {
  name                 = "internal"
  resource_group_name  = azurerm_resource_group.main.name
  virtual_network_name = azurerm_virtual_network.main.name
  address_prefixes     = [var.azurerm_vpc_subnet_cidr]

}

resource "azurerm_network_interface" "main" {
  name                = each.value.instance_name
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  for_each            = { for node in var.azure_instances : node.instance_name => node }

  ip_configuration {
    name                          = var.azurerm_prefix
    subnet_id                     = azurerm_subnet.internal.id
    private_ip_address_allocation = "Dynamic"
    public_ip_address_id          = azurerm_public_ip.main[each.key].id
  }

  tags = {
    daiteap-env-id = var.azurerm_environment_id,
    daiteap-username = var.azurerm_daiteap_username,
    daiteap-user-email = var.azurerm_daiteap_user_email,
    daiteap-platform-url = var.azurerm_daiteap_platform_url,
    daiteap-workspace-name = var.azurerm_daiteap_workspace_name
  }
}

resource "azurerm_public_ip" "main" {
  name                    = each.value.instance_name
  location                = azurerm_resource_group.main.location
  resource_group_name     = azurerm_resource_group.main.name
  allocation_method       = "Static"
  idle_timeout_in_minutes = 30
  for_each                = { for node in var.azure_instances : node.instance_name => node }

  tags = {
    daiteap-env-id = var.azurerm_environment_id,
    daiteap-username = var.azurerm_daiteap_username,
    daiteap-user-email = var.azurerm_daiteap_user_email,
    daiteap-platform-url = var.azurerm_daiteap_platform_url,
    daiteap-workspace-name = var.azurerm_daiteap_workspace_name
  }
}

resource "azurerm_private_dns_zone" "azure-private-zone" {
  name                = var.azurerm_internal_dns_zone
  resource_group_name = azurerm_resource_group.main.name

  tags = {
    daiteap-env-id = var.azurerm_environment_id,
    daiteap-username = var.azurerm_daiteap_username,
    daiteap-user-email = var.azurerm_daiteap_user_email,
    daiteap-platform-url = var.azurerm_daiteap_platform_url,
    daiteap-workspace-name = var.azurerm_daiteap_workspace_name
  }
}

resource "azurerm_private_dns_zone_virtual_network_link" "azure-private-zone-link" {
  name                  = "private-zone"
  resource_group_name   = azurerm_resource_group.main.name
  private_dns_zone_name = azurerm_private_dns_zone.azure-private-zone.name
  virtual_network_id    = azurerm_virtual_network.main.id
  registration_enabled  = true

  tags = {
    daiteap-env-id = var.azurerm_environment_id,
    daiteap-username = var.azurerm_daiteap_username,
    daiteap-user-email = var.azurerm_daiteap_user_email,
    daiteap-platform-url = var.azurerm_daiteap_platform_url,
    daiteap-workspace-name = var.azurerm_daiteap_workspace_name
  }
}

resource "azurerm_availability_set" "default" {
  name                        = var.azurerm_prefix
  location                    = azurerm_resource_group.main.location
  resource_group_name         = azurerm_resource_group.main.name
  platform_fault_domain_count = 2

  tags = {
    daiteap-env-id = var.azurerm_environment_id,
    daiteap-username = var.azurerm_daiteap_username,
    daiteap-user-email = var.azurerm_daiteap_user_email,
    daiteap-platform-url = var.azurerm_daiteap_platform_url,
    daiteap-workspace-name = var.azurerm_daiteap_workspace_name
  }
}

resource "azurerm_route_table" "default" {
  name                = var.azurerm_prefix
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name

  tags = {
    daiteap-env-id = var.azurerm_environment_id,
    daiteap-username = var.azurerm_daiteap_username,
    daiteap-user-email = var.azurerm_daiteap_user_email,
    daiteap-platform-url = var.azurerm_daiteap_platform_url,
    daiteap-workspace-name = var.azurerm_daiteap_workspace_name
  }
}

resource "azurerm_network_security_group" "default" {
  name                = var.azurerm_prefix
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name

  security_rule {
    name                       = "AllowAll"
    priority                   = 1000
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "*"
    source_port_range          = "*"
    destination_port_range     = "*"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }

  tags = {
    daiteap-env-id = var.azurerm_environment_id,
    daiteap-username = var.azurerm_daiteap_username,
    daiteap-user-email = var.azurerm_daiteap_user_email,
    daiteap-platform-url = var.azurerm_daiteap_platform_url,
    daiteap-workspace-name = var.azurerm_daiteap_workspace_name
  }
}

resource "azurerm_managed_disk" "os-disk" {
  name                 = each.value.instance_name
  location             = azurerm_resource_group.main.location
  resource_group_name  = azurerm_resource_group.main.name
  storage_account_type = "Standard_LRS"
  create_option        = "FromImage"
  disk_size_gb         = "50"
  for_each             = { for node in var.azure_instances : node.instance_name => node }

  gallery_image_reference_id = "/subscriptions/af5bb549-d639-4ea4-9632-5b6aa6881cd8/resourceGroups/Packer/providers/Microsoft.Compute/galleries/Packer_image_gallery/images/dlcm-ubuntu-1804/versions/1.0.1"
}

resource "azurerm_linux_virtual_machine" "main" {
  name                  = each.value.instance_name
  location              = azurerm_resource_group.main.location
  resource_group_name   = azurerm_resource_group.main.name
  network_interface_ids = [azurerm_network_interface.main[each.key].id]
  size                  = each.value.instance_type
  for_each              = { for node in var.azure_instances : node.instance_name => node }
  admin_username        = var.azure_user

  source_image_reference {
    publisher = each.value.image_publisher
    offer     = each.value.image_offer
    sku       = each.value.image_sku
    version   = each.value.image_version
  }

  availability_set_id = azurerm_availability_set.default.id

  os_disk {
    caching              = "ReadWrite"
    storage_account_type = "Standard_LRS"
    disk_size_gb         = each.value.instance_storage
  }

  admin_ssh_key {
    username   = var.azure_user
    public_key = file("/var/.ssh/id_rsa.pub")
  }

  tags = {
    daiteap-env-id = var.azurerm_environment_id,
    daiteap-username = var.azurerm_daiteap_username,
    daiteap-user-email = var.azurerm_daiteap_user_email,
    daiteap-platform-url = var.azurerm_daiteap_platform_url,
    daiteap-workspace-name = var.azurerm_daiteap_workspace_name
  }
}

resource "null_resource" "azure_instances_exec" {
  depends_on = [azurerm_linux_virtual_machine.main]

  for_each = { for node in var.azure_instances : node.instance_name => node }

  provisioner "remote-exec" {
    connection {
      type        = "ssh"
      host        = azurerm_public_ip.main[each.key].ip_address
      private_key = file("/var/.ssh/id_rsa")
      user        = var.azure_user
    }
    inline = [
      "ls"
    ]
  }
}
