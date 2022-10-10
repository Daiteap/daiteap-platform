variable "aws_onpremise_network_cidr" {
  default = "10.0.0.0/16"
}

variable "aws_onpremise_vpn_gateway_internet_ip" {
  default = "1.1.1.1"
}


# AWS
resource "aws_customer_gateway" "onpremise_main" {
  bgp_asn    = 65000
  ip_address = var.aws_onpremise_vpn_gateway_internet_ip
  type       = "ipsec.1"

  tags = {
    Name = var.aws_vpc_name
    daiteap-env-id = var.aws_environment_id,
    daiteap-username = var.aws_daiteap_username,
    daiteap-user-email = var.aws_daiteap_user_email,
    daiteap-platform-url = var.aws_daiteap_platform_url,
    daiteap-workspace-name = var.aws_daiteap_workspace_name
  }
}

resource "aws_route" "onpremise" {
  route_table_id         = aws_vpc.default.main_route_table_id
  destination_cidr_block = var.aws_onpremise_network_cidr
  gateway_id             = aws_vpn_gateway.default.id
}

resource "aws_vpn_gateway_route_propagation" "onpremise" {
  vpn_gateway_id = aws_vpn_gateway.default.id
  route_table_id = aws_vpc.default.main_route_table_id
}

resource "aws_vpn_connection" "onpremise" {
  vpn_gateway_id      = aws_vpn_gateway.default.id
  customer_gateway_id = aws_customer_gateway.onpremise_main.id
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

resource "aws_vpn_connection_route" "onpremise" {
  destination_cidr_block = var.aws_onpremise_network_cidr
  vpn_connection_id      = aws_vpn_connection.onpremise.id
}
