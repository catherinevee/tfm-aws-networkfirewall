# ==============================================================================
# Transit Gateway Configuration
# ==============================================================================

# Transit Gateway - Central networking hub for traffic inspection
resource "aws_ec2_transit_gateway" "main" {
  description = var.tgw_description
  
  # Basic Configuration
  auto_accept_shared_attachments = var.transit_gateway_auto_accept_shared_attachments
  default_route_table_association = var.transit_gateway_default_route_table_association
  default_route_table_propagation = var.transit_gateway_default_route_table_propagation
  dns_support = var.transit_gateway_dns_support
  vpn_ecmp_support = var.transit_gateway_vpn_ecmp_support
  multicast_support = var.transit_gateway_multicast_support
  
  # Advanced Configuration
  amazon_side_asn = var.transit_gateway_asn
  
  tags = merge(
    var.common_tags,
    {
      Name = "${var.name_prefix}-tgw"
      Type = "transit-gateway"
      Component = "networking"
    }
  )
}

# Transit Gateway Route Tables
resource "aws_ec2_transit_gateway_route_table" "inspection" {
  transit_gateway_id = aws_ec2_transit_gateway.main.id
  
  tags = merge(
    var.common_tags,
    {
      Name = "${var.name_prefix}-tgw-rt-inspection"
      Type = "transit-gateway-route-table"
      Component = "routing"
      Purpose = "inspection"
    }
  )
}

resource "aws_ec2_transit_gateway_route_table" "private" {
  transit_gateway_id = aws_ec2_transit_gateway.main.id
  
  tags = merge(
    var.common_tags,
    {
      Name = "${var.name_prefix}-tgw-rt-private"
      Type = "transit-gateway-route-table"
      Component = "routing"
      Purpose = "private"
    }
  )
}
