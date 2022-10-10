# AWS
resource "aws_customer_gateway" "alicloud_main" {
  bgp_asn    = 65000
  ip_address = alicloud_vpn_gateway.vpngw_aws.internet_ip
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

resource "aws_route" "alicloud" {
  route_table_id         = aws_vpc.default.main_route_table_id
  destination_cidr_block = var.alicloud_vswitch_cidr
  gateway_id             = aws_vpn_gateway.default.id
}

resource "aws_vpn_gateway_route_propagation" "alicloud" {
  vpn_gateway_id = aws_vpn_gateway.default.id
  route_table_id = aws_vpc.default.main_route_table_id
}

resource "aws_vpn_connection" "alicloud" {
  vpn_gateway_id      = aws_vpn_gateway.default.id
  customer_gateway_id = aws_customer_gateway.alicloud_main.id
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

resource "aws_vpn_connection_route" "alicloud" {
  destination_cidr_block = var.alicloud_vswitch_cidr
  vpn_connection_id      = aws_vpn_connection.alicloud.id
}

# Alicloud
resource "alicloud_vpn_gateway" "vpngw_aws" {
  name                 = "${var.alicloud_vpc_name}-vgw-aws"
  vpc_id               = alicloud_vpc.vpc.id
  bandwidth            = "10"
  enable_ssl           = true
  instance_charge_type = "PostPaid"
  vswitch_id           = alicloud_vswitch.vswitch.id

  description = var.alicloud_environment_id
}

resource "alicloud_vpn_customer_gateway" "cgw_aws1" {
  name       = "${var.alicloud_vpc_name}-cgw-aws1"
  ip_address = aws_vpn_connection.alicloud.tunnel1_address

  description = var.alicloud_environment_id
}

resource "alicloud_vpn_customer_gateway" "cgw_aws2" {
  name       = "${var.alicloud_vpc_name}-cgw-aws2"
  ip_address = aws_vpn_connection.alicloud.tunnel2_address

  description = var.alicloud_environment_id
}

resource "alicloud_vpn_connection" "vpn_aws1" {
  name                = "${var.alicloud_vpc_name}-vpn-aws1"
  vpn_gateway_id      = alicloud_vpn_gateway.vpngw_aws.id
  customer_gateway_id = alicloud_vpn_customer_gateway.cgw_aws1.id
  local_subnet        = [var.alicloud_vswitch_cidr]
  remote_subnet       = [var.aws_vpc_cidr]
  effect_immediately  = true
  ike_config {
    ike_auth_alg = "sha1"
    ike_enc_alg  = "aes"
    ike_version  = "ikev1"
    ike_mode     = "main"
    ike_pfs      = "group2"
    ike_lifetime = 86400
    psk          = aws_vpn_connection.alicloud.tunnel1_preshared_key
    ike_local_id = alicloud_vpn_gateway.vpngw_aws.internet_ip
    ike_remote_id = aws_vpn_connection.alicloud.tunnel1_address
  }
  ipsec_config {
    ipsec_pfs      = "group2"
    ipsec_enc_alg  = "aes"
    ipsec_auth_alg = "sha1"
    ipsec_lifetime = 86400
  }
}

resource "alicloud_vpn_connection" "vpn_aws2" {
  name                = "${var.alicloud_vpc_name}-vpn-aws2"
  vpn_gateway_id      = alicloud_vpn_gateway.vpngw_aws.id
  customer_gateway_id = alicloud_vpn_customer_gateway.cgw_aws2.id
  local_subnet        = [var.alicloud_vswitch_cidr]
  remote_subnet       = [var.aws_vpc_cidr]
  effect_immediately  = true
  ike_config {
    ike_auth_alg = "sha1"
    ike_enc_alg  = "aes"
    ike_version  = "ikev1"
    ike_mode     = "main"
    ike_pfs      = "group2"
    ike_lifetime = 86400
    psk          = aws_vpn_connection.alicloud.tunnel2_preshared_key
    ike_local_id = alicloud_vpn_gateway.vpngw_aws.internet_ip
    ike_remote_id = aws_vpn_connection.alicloud.tunnel2_address
  }
  ipsec_config {
    ipsec_pfs      = "group2"
    ipsec_enc_alg  = "aes"
    ipsec_auth_alg = "sha1"
    ipsec_lifetime = 86400
  }
}

resource "alicloud_route_entry" "vpn_aws" {
  route_table_id        = alicloud_vpc.vpc.route_table_id
  destination_cidrblock = var.aws_vpc_cidr
  nexthop_type          = "VpnGateway"
  nexthop_id            = alicloud_vpn_gateway.vpngw_aws.id
}
