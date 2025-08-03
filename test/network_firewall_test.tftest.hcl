variables {
  name_prefix = "test-firewall"
  firewall_vpc_cidr = "10.100.0.0/16"
  availability_zones = ["us-east-1a", "us-east-1b"]
}

run "basic_network_firewall_configuration" {
  command = plan

  assert {
    condition = aws_vpc.firewall.cidr_block == var.firewall_vpc_cidr
    error_message = "VPC CIDR block does not match input variable"
  }

  assert {
    condition = length(aws_subnet.firewall_public) == length(var.availability_zones)
    error_message = "Number of public subnets does not match number of availability zones"
  }
}

run "verify_transit_gateway_configuration" {
  command = plan

  assert {
    condition = aws_ec2_transit_gateway.main.amazon_side_asn == 64512
    error_message = "Transit Gateway ASN not set to default value"
  }
}
