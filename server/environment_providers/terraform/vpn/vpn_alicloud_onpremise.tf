variable "alicloud_onpremise_shared_secret" {
  default = "secret"
}

variable "alicloud_onpremise_network_cidr" {
  default = "10.0.0.0/16"
}

variable "alicloud_onpremise_vpn_gateway_internet_ip" {
  default = "1.1.1.1"
}


# Alicloud
resource "alicloud_vpn_gateway" "vpngw_onpremise" {
  name                 = "${var.alicloud_vpc_name}-vgw-onpremise"
  vpc_id               = alicloud_vpc.vpc.id
  bandwidth            = "10"
  enable_ssl           = true
  instance_charge_type = "PostPaid"
  vswitch_id           = alicloud_vswitch.vswitch.id
}

resource "alicloud_vpn_customer_gateway" "cgw_onpremise" {
  name       = "${var.alicloud_vpc_name}-cgw-onpremise"
  ip_address = alicloud_onpremise_vpn_gateway_internet_ip
}

resource "alicloud_vpn_connection" "onpremise" {
  name                = "${var.alicloud_vpc_name}-vpn-onpremise"
  vpn_gateway_id      = alicloud_vpn_gateway.vpngw_onpremise.id
  customer_gateway_id = alicloud_vpn_customer_gateway.cgw_onpremise.id
  local_subnet        = [var.alicloud_vswitch_cidr]
  remote_subnet       = [var.alicloud_onpremise_network_cidr]
  effect_immediately  = true
  ike_config {
    ike_auth_alg = "sha1"
    ike_enc_alg  = "aes256"
    ike_version  = "ikev2"
    ike_mode     = "main"
    ike_pfs      = "group14"
    ike_lifetime = 28800
    psk          = var.alicloud_onpremise_shared_secret
  }
  ipsec_config {
    ipsec_pfs      = "group14"
    ipsec_enc_alg  = "aes256"
    ipsec_auth_alg = "sha1"
    ipsec_lifetime = 28800
  }
}

resource "alicloud_route_entry" "onpremise" {
  route_table_id        = alicloud_vpc.vpc.route_table_id
  destination_cidrblock = var.alicloud_onpremise_network_cidr
  nexthop_type          = "VpnGateway"
  nexthop_id            = alicloud_vpn_gateway.vpngw_onpremise.id
}
