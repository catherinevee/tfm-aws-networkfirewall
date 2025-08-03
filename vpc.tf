# ==============================================================================
# VPC Configuration
# ==============================================================================

resource "aws_vpc" "firewall" {
  cidr_block           = var.firewall_vpc_cidr
  enable_dns_hostnames = var.enable_dns_hostnames
  enable_dns_support   = var.enable_dns_support
  instance_tenancy     = var.vpc_instance_tenancy
  ipv4_ipam_pool_id    = var.vpc_ipv4_ipam_pool_id
  ipv4_netmask_length  = var.vpc_ipv4_netmask_length

  tags = merge(
    var.common_tags,
    {
      Name = "${var.name_prefix}-firewall-vpc"
      Type = "vpc"
      Component = "networking"
      Purpose = "firewall"
    }
  )
}

# Public Subnets
resource "aws_subnet" "firewall_public" {
  count             = length(var.firewall_public_subnets)
  vpc_id            = aws_vpc.firewall.id
  cidr_block        = var.firewall_public_subnets[count.index]
  availability_zone = var.availability_zones[count.index]

  tags = merge(
    var.common_tags,
    {
      Name = "${var.name_prefix}-firewall-public-${count.index + 1}"
      Type = "subnet"
      Component = "networking"
      Purpose = "firewall-public"
    }
  )
}

# Private Subnets
resource "aws_subnet" "firewall_private" {
  count             = length(var.firewall_private_subnets)
  vpc_id            = aws_vpc.firewall.id
  cidr_block        = var.firewall_private_subnets[count.index]
  availability_zone = var.availability_zones[count.index]

  tags = merge(
    var.common_tags,
    {
      Name = "${var.name_prefix}-firewall-private-${count.index + 1}"
      Type = "subnet"
      Component = "networking"
      Purpose = "firewall-private"
    }
  )
}
