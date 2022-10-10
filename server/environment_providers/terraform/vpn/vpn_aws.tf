# Create a "Virtual Private Gateway" in AWS
resource "aws_vpn_gateway" "default" {
  # Attach to the VPC.
  vpc_id = aws_vpc.default.id

  tags = {
    Name = "${var.aws_vpc_name}-vpn-gw"
    daiteap-env-id = var.aws_environment_id,
    daiteap-username = var.aws_daiteap_username,
    daiteap-user-email = var.aws_daiteap_user_email,
    daiteap-platform-url = var.aws_daiteap_platform_url,
    daiteap-workspace-name = var.aws_daiteap_workspace_name
  }
}
