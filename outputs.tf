# =============================================================================
# Outputs for Transit Gateway → Network Firewall → VPC Traffic Inspection
# =============================================================================

output "transit_gateway_id" {
  description = "ID of the Transit Gateway"
  value       = aws_ec2_transit_gateway.main.id
}

output "transit_gateway_arn" {
  description = "ARN of the Transit Gateway"
  value       = aws_ec2_transit_gateway.main.arn
}

output "transit_gateway_inspection_route_table_id" {
  description = "ID of the Transit Gateway inspection route table"
  value       = aws_ec2_transit_gateway_route_table.inspection.id
}

output "transit_gateway_private_route_table_id" {
  description = "ID of the Transit Gateway private route table"
  value       = aws_ec2_transit_gateway_route_table.private.id
}

output "firewall_vpc_id" {
  description = "ID of the Network Firewall VPC"
  value       = aws_vpc.firewall.id
}

output "firewall_vpc_cidr_block" {
  description = "CIDR block of the Network Firewall VPC"
  value       = aws_vpc.firewall.cidr_block
}

output "firewall_public_subnet_ids" {
  description = "IDs of the public subnets in the firewall VPC"
  value       = aws_subnet.firewall_public[*].id
}

output "firewall_private_subnet_ids" {
  description = "IDs of the private subnets in the firewall VPC"
  value       = aws_subnet.firewall_private[*].id
}

output "firewall_public_subnet_cidr_blocks" {
  description = "CIDR blocks of the public subnets in the firewall VPC"
  value       = aws_subnet.firewall_public[*].cidr_block
}

output "firewall_private_subnet_cidr_blocks" {
  description = "CIDR blocks of the private subnets in the firewall VPC"
  value       = aws_subnet.firewall_private[*].cidr_block
}

output "network_firewall_id" {
  description = "ID of the Network Firewall"
  value       = aws_networkfirewall_firewall.main.id
}

output "network_firewall_arn" {
  description = "ARN of the Network Firewall"
  value       = aws_networkfirewall_firewall.main.arn
}

output "network_firewall_name" {
  description = "Name of the Network Firewall"
  value       = aws_networkfirewall_firewall.main.name
}

output "network_firewall_status" {
  description = "Status of the Network Firewall"
  value       = aws_networkfirewall_firewall.main.firewall_status
}

output "firewall_policy_id" {
  description = "ID of the Network Firewall Policy"
  value       = aws_networkfirewall_firewall_policy.main.id
}

output "firewall_policy_arn" {
  description = "ARN of the Network Firewall Policy"
  value       = aws_networkfirewall_firewall_policy.main.arn
}

output "stateless_rule_group_id" {
  description = "ID of the stateless rule group"
  value       = aws_networkfirewall_rule_group.stateless.id
}

output "stateless_rule_group_arn" {
  description = "ARN of the stateless rule group"
  value       = aws_networkfirewall_rule_group.stateless.arn
}

output "stateful_rule_group_id" {
  description = "ID of the stateful rule group"
  value       = aws_networkfirewall_rule_group.stateful.id
}

output "stateful_rule_group_arn" {
  description = "ARN of the stateful rule group"
  value       = aws_networkfirewall_rule_group.stateful.arn
}

output "transit_gateway_vpc_attachment_id" {
  description = "ID of the Transit Gateway VPC attachment for the firewall VPC"
  value       = aws_ec2_transit_gateway_vpc_attachment.firewall.id
}

output "transit_gateway_vpc_attachment_arn" {
  description = "ARN of the Transit Gateway VPC attachment for the firewall VPC"
  value       = aws_ec2_transit_gateway_vpc_attachment.firewall.arn
}

output "firewall_logs_s3_bucket" {
  description = "Name of the S3 bucket for firewall logs"
  value       = var.enable_s3_logging ? aws_s3_bucket.firewall_logs[0].bucket : null
}

output "firewall_logs_s3_bucket_arn" {
  description = "ARN of the S3 bucket for firewall logs"
  value       = var.enable_s3_logging ? aws_s3_bucket.firewall_logs[0].arn : null
}

output "cloudwatch_log_group_name" {
  description = "Name of the CloudWatch log group for firewall logs"
  value       = var.enable_cloudwatch_logging ? aws_cloudwatch_log_group.firewall[0].name : null
}

output "cloudwatch_log_group_arn" {
  description = "ARN of the CloudWatch log group for firewall logs"
  value       = var.enable_cloudwatch_logging ? aws_cloudwatch_log_group.firewall[0].arn : null
}

output "firewall_security_group_id" {
  description = "ID of the security group for the Network Firewall"
  value       = aws_security_group.firewall.id
}

output "firewall_security_group_arn" {
  description = "ARN of the security group for the Network Firewall"
  value       = aws_security_group.firewall.arn
}

output "vpc_endpoint_ids" {
  description = "IDs of the VPC endpoints created for the firewall VPC"
  value       = aws_vpc_endpoint.firewall[*].id
}

output "vpc_endpoint_arns" {
  description = "ARNs of the VPC endpoints created for the firewall VPC"
  value       = aws_vpc_endpoint.firewall[*].arn
}

output "firewall_iam_role_arn" {
  description = "ARN of the IAM role for the Network Firewall"
  value       = aws_iam_role.firewall.arn
}

output "firewall_iam_role_name" {
  description = "Name of the IAM role for the Network Firewall"
  value       = aws_iam_role.firewall.name
}

output "internet_gateway_id" {
  description = "ID of the Internet Gateway for the firewall VPC"
  value       = aws_internet_gateway.firewall.id
}

output "firewall_public_route_table_id" {
  description = "ID of the public route table for the firewall VPC"
  value       = aws_route_table.firewall_public.id
}

output "firewall_private_route_table_id" {
  description = "ID of the private route table for the firewall VPC"
  value       = aws_route_table.firewall_private.id
}

# Composite outputs for easier integration
output "network_firewall_endpoints" {
  description = "Network Firewall endpoint information"
  value = {
    id   = aws_networkfirewall_firewall.main.id
    arn  = aws_networkfirewall_firewall.main.arn
    name = aws_networkfirewall_firewall.main.name
    status = aws_networkfirewall_firewall.main.firewall_status
  }
}

output "transit_gateway_info" {
  description = "Transit Gateway information"
  value = {
    id          = aws_ec2_transit_gateway.main.id
    arn         = aws_ec2_transit_gateway.main.arn
    description = aws_ec2_transit_gateway.main.description
    route_tables = {
      inspection = aws_ec2_transit_gateway_route_table.inspection.id
      private    = aws_ec2_transit_gateway_route_table.private.id
    }
  }
}

output "firewall_vpc_info" {
  description = "Firewall VPC information"
  value = {
    id            = aws_vpc.firewall.id
    cidr_block    = aws_vpc.firewall.cidr_block
    subnets = {
      public = {
        ids         = aws_subnet.firewall_public[*].id
        cidr_blocks = aws_subnet.firewall_public[*].cidr_block
      }
      private = {
        ids         = aws_subnet.firewall_private[*].id
        cidr_blocks = aws_subnet.firewall_private[*].cidr_block
      }
    }
  }
}

output "logging_info" {
  description = "Logging configuration information"
  value = {
    s3_bucket = var.enable_s3_logging ? {
      name = aws_s3_bucket.firewall_logs[0].bucket
      arn  = aws_s3_bucket.firewall_logs[0].arn
    } : null
    cloudwatch = var.enable_cloudwatch_logging ? {
      name = aws_cloudwatch_log_group.firewall[0].name
      arn  = aws_cloudwatch_log_group.firewall[0].arn
    } : null
  }
} 