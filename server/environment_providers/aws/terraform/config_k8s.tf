variable "aws_access_key_id" {
  default = ""
}
variable "aws_secret_access_key" {
  default = ""
}

variable "aws_environment_id" {
  default = "test"
}

variable "aws_daiteap_username" {
  default = "test"
}

variable "aws_daiteap_user_email" {
  default = "test"
}

variable "aws_daiteap_platform_url" {
  default = "test"
}

variable "aws_daiteap_workspace_name" {
  default = "test"
}

variable "aws_private_key_path" {
  default     = "/var/.ssh/id_rsa"
}

variable "aws_internal_dns_zone" {}

variable "aws_public_key_name" {
  description = "SSH key name in your AWS account for AWS instances."
  default     = "id_rsa"
}

variable "aws_public_key_path" {
  description = "Path to the private key specified by aws_public_key_name."
  default     = "/var/.ssh/id_rsa.pub"
}

variable "aws_vpc_name" {
  default = "clustername"
}

variable "aws_region" {
  description = "The region of AWS, for AMI lookups."
  default     = "eu-central-1"
}

variable "aws_longhorn_volume_size" {
  default = 100
}

variable "aws_user" {
  default = "ubuntu"
}

variable "aws_instances" {
  type = list(
    object({
      instance_name    = string,
      image_owner      = string,
      instance_image   = string,
      instance_type    = string,
      zone             = string,
      instance_storage = string,
      subnet_cidr     = string
  }))
}

variable "aws_subnets" {
  type = list(
    object({
      cidr = string,
      zone = string
  }))
}

variable "aws_vpc_cidr" {
  default = "10.0.0.0/16"
}

data "aws_ami" "aws_image" {
  for_each = { for node in var.aws_instances : node.instance_name => node }

  most_recent = true

  filter {
    name   = "name"
    values = [each.value.instance_image]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }

  owners = [each.value.image_owner]
}

provider "aws" {
  region     = var.aws_region
  access_key = var.aws_access_key_id
  secret_key = var.aws_secret_access_key
}

# Create a VPC
resource "aws_vpc" "default" {
  cidr_block           = var.aws_vpc_cidr
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name           = var.aws_vpc_name
    daiteap-env-id = var.aws_environment_id,
    daiteap-username = var.aws_daiteap_username,
    daiteap-user-email = var.aws_daiteap_user_email,
    daiteap-platform-url = var.aws_daiteap_platform_url,
    daiteap-workspace-name = var.aws_daiteap_workspace_name
  }
}

resource "aws_route53_zone" "private-zone" {
  name = var.aws_internal_dns_zone

  vpc {
    vpc_id = aws_vpc.default.id
  }

  tags = {
    daiteap-env-id = var.aws_environment_id,
    daiteap-username = var.aws_daiteap_username,
    daiteap-user-email = var.aws_daiteap_user_email,
    daiteap-platform-url = var.aws_daiteap_platform_url,
    daiteap-workspace-name = var.aws_daiteap_workspace_name
  }
  comment = var.aws_environment_id
}

resource "aws_route53_record" "aws_nodes_dns_records" {
  zone_id  = aws_route53_zone.private-zone.zone_id
  for_each = { for node in var.aws_instances : node.instance_name => node }
  name     = "${each.value.instance_name}.${aws_route53_zone.private-zone.name}"
  type     = "A"
  ttl      = "300"
  records  = [aws_instance.aws_nodes[each.key].private_ip]
}

resource "aws_internet_gateway" "default" {
  vpc_id = aws_vpc.default.id

  tags = {
    daiteap-env-id = var.aws_environment_id,
    daiteap-username = var.aws_daiteap_username,
    daiteap-user-email = var.aws_daiteap_user_email,
    daiteap-platform-url = var.aws_daiteap_platform_url,
    daiteap-workspace-name = var.aws_daiteap_workspace_name
  }
}

resource "aws_route" "internet_access" {
  route_table_id         = aws_vpc.default.main_route_table_id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.default.id
}

resource "aws_subnet" "default" {
  vpc_id                  = aws_vpc.default.id
  availability_zone       = each.value.zone
  for_each                = { for subnet in var.aws_subnets : subnet.cidr => subnet }
  cidr_block              = each.value.cidr
  map_public_ip_on_launch = true

  tags = {
    daiteap-env-id = var.aws_environment_id,
    daiteap-username = var.aws_daiteap_username,
    daiteap-user-email = var.aws_daiteap_user_email,
    daiteap-platform-url = var.aws_daiteap_platform_url,
    daiteap-workspace-name = var.aws_daiteap_workspace_name
  }
}

# Default security group
resource "aws_security_group" "default" {
  name        = "${var.aws_vpc_name}-default"
  description = "Used in the terraform"
  vpc_id      = aws_vpc.default.id

  # Allow internal traffic
  ingress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = [aws_vpc.default.cidr_block]
  }

  # Allow internal traffic
  ingress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # outbound internet access
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    daiteap-env-id = var.aws_environment_id,
    daiteap-username = var.aws_daiteap_username,
    daiteap-user-email = var.aws_daiteap_user_email,
    daiteap-platform-url = var.aws_daiteap_platform_url,
    daiteap-workspace-name = var.aws_daiteap_workspace_name
  }
}

resource "aws_key_pair" "auth" {
  key_name   = var.aws_public_key_name
  public_key = file(var.aws_public_key_path)

  tags = {
    daiteap-env-id = var.aws_environment_id,
    daiteap-username = var.aws_daiteap_username,
    daiteap-user-email = var.aws_daiteap_user_email,
    daiteap-platform-url = var.aws_daiteap_platform_url,
    daiteap-workspace-name = var.aws_daiteap_workspace_name
  }
}


resource "aws_eip" "lb" {
  instance = aws_instance.aws_nodes[each.key].id
  vpc      = true
  for_each = { for node in var.aws_instances : node.instance_name => node }

  tags = {
    daiteap-env-id = var.aws_environment_id,
    daiteap-username = var.aws_daiteap_username,
    daiteap-user-email = var.aws_daiteap_user_email,
    daiteap-platform-url = var.aws_daiteap_platform_url,
    daiteap-workspace-name = var.aws_daiteap_workspace_name
  }
}

resource "aws_ebs_volume" "longhorn" {
  availability_zone = each.value.zone
  size              = var.aws_longhorn_volume_size
  type              = "gp2"
  for_each          = { for node in var.aws_instances : node.instance_name => node }

  tags = {
    Name                                        = "${each.value.instance_name}-longhorn"
    "kubernetes.io/cluster/${var.aws_vpc_name}" = "owned"
    daiteap-env-id                              = var.aws_environment_id,
    daiteap-username = var.aws_daiteap_username,
    daiteap-user-email = var.aws_daiteap_user_email,
    daiteap-platform-url = var.aws_daiteap_platform_url,
    daiteap-workspace-name = var.aws_daiteap_workspace_name
  }
}

resource "aws_volume_attachment" "longhorn" {
  device_name  = "/dev/sdf"
  volume_id    = aws_ebs_volume.longhorn[each.key].id
  instance_id  = aws_instance.aws_nodes[each.key].id
  for_each     = { for node in var.aws_instances : node.instance_name => node }
}

resource "aws_instance" "aws_nodes" {
  instance_type               = each.value.instance_type
  monitoring                  = false
  associate_public_ip_address = true
  availability_zone           = each.value.zone

  ami                    = data.aws_ami.aws_image[each.key].id
  for_each               = { for node in var.aws_instances : node.instance_name => node }
  key_name               = aws_key_pair.auth.id
  vpc_security_group_ids = [aws_security_group.default.id]
  subnet_id              = aws_subnet.default[each.value.subnet_cidr].id
  user_data              = file("../../../../environment_providers/aws/terraform/aws-init-script.sh")

  root_block_device {
    volume_size = each.value.instance_storage
  }

  tags = {
    Name                                        = each.value.instance_name
    "kubernetes.io/cluster/${var.aws_vpc_name}" = "owned"
    daiteap-env-id                              = var.aws_environment_id,
    daiteap-username = var.aws_daiteap_username,
    daiteap-user-email = var.aws_daiteap_user_email,
    daiteap-platform-url = var.aws_daiteap_platform_url,
    daiteap-workspace-name = var.aws_daiteap_workspace_name
  }
}

resource "null_resource" "longhorn" {
  depends_on = [aws_volume_attachment.longhorn]

  connection {
    type        = "ssh"
    user        = var.aws_user
    private_key = file(var.aws_private_key_path)
    host        = aws_eip.lb[each.key].public_ip
  }

  for_each = { for node in var.aws_instances : node.instance_name => node }

  provisioner "remote-exec" {
    inline = [
      "sudo mkdir -p /var/lib/longhorn",
      "sudo chown -R ${var.aws_user}:${var.aws_user} /var/lib/longhorn",
      "sudo chmod 777 /var/lib/longhorn",
      "sudo mkfs.ext4 /dev/disk/by-id/nvme-Amazon_Elastic_Block_Store_${replace(aws_volume_attachment.longhorn[each.key].volume_id, "-", "")}",
      "sudo echo '/dev/disk/by-id/nvme-Amazon_Elastic_Block_Store_${replace(aws_volume_attachment.longhorn[each.key].volume_id, "-", "")} /var/lib/longhorn ext4 defaults 0 0' | sudo tee -a /etc/fstab",
      "sudo mount -a"
    ]
  }
}