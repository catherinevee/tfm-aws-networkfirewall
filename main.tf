# =============================================================================
# Transit Gateway → Network Firewall → VPC Traffic Inspection Architecture
# =============================================================================

# Transit Gateway
resource "aws_ec2_transit_gateway" "main" {
  description = var.tgw_description
  
  auto_accept_shared_attachments = var.transit_gateway_auto_accept_shared_attachments
  default_route_table_association = var.transit_gateway_default_route_table_association
  default_route_table_propagation = var.transit_gateway_default_route_table_propagation
  dns_support = var.transit_gateway_dns_support
  vpn_ecmp_support = var.transit_gateway_vpn_ecmp_support
  multicast_support = var.transit_gateway_multicast_support
  
  tags = merge(
    var.common_tags,
    {
      Name = "${var.name_prefix}-tgw"
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
    }
  )
}

resource "aws_ec2_transit_gateway_route_table" "private" {
  transit_gateway_id = aws_ec2_transit_gateway.main.id
  tags = merge(
    var.common_tags,
    {
      Name = "${var.name_prefix}-tgw-rt-private"
    }
  )
}

# VPC for Network Firewall
resource "aws_vpc" "firewall" {
  cidr_block           = var.firewall_vpc_cidr
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = merge(
    var.common_tags,
    {
      Name = "${var.name_prefix}-firewall-vpc"
    }
  )
}

# Subnets for Network Firewall
resource "aws_subnet" "firewall_public" {
  count             = length(var.firewall_public_subnets)
  vpc_id            = aws_vpc.firewall.id
  cidr_block        = var.firewall_public_subnets[count.index]
  availability_zone = var.availability_zones[count.index]

  tags = merge(
    var.common_tags,
    {
      Name = "${var.name_prefix}-firewall-public-${var.availability_zones[count.index]}"
      Tier = "Public"
    }
  )
}

resource "aws_subnet" "firewall_private" {
  count             = length(var.firewall_private_subnets)
  vpc_id            = aws_vpc.firewall.id
  cidr_block        = var.firewall_private_subnets[count.index]
  availability_zone = var.availability_zones[count.index]

  tags = merge(
    var.common_tags,
    {
      Name = "${var.name_prefix}-firewall-private-${var.availability_zones[count.index]}"
      Tier = "Private"
    }
  )
}

# Internet Gateway for Firewall VPC
resource "aws_internet_gateway" "firewall" {
  vpc_id = aws_vpc.firewall.id

  tags = merge(
    var.common_tags,
    {
      Name = "${var.name_prefix}-firewall-igw"
    }
  )
}

# Route Tables for Firewall VPC
resource "aws_route_table" "firewall_public" {
  vpc_id = aws_vpc.firewall.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.firewall.id
  }

  tags = merge(
    var.common_tags,
    {
      Name = "${var.name_prefix}-firewall-public-rt"
    }
  )
}

resource "aws_route_table" "firewall_private" {
  vpc_id = aws_vpc.firewall.id

  tags = merge(
    var.common_tags,
    {
      Name = "${var.name_prefix}-firewall-private-rt"
    }
  )
}

# Route Table Associations
resource "aws_route_table_association" "firewall_public" {
  count          = length(var.firewall_public_subnets)
  subnet_id      = aws_subnet.firewall_public[count.index].id
  route_table_id = aws_route_table.firewall_public.id
}

resource "aws_route_table_association" "firewall_private" {
  count          = length(var.firewall_private_subnets)
  subnet_id      = aws_subnet.firewall_private[count.index].id
  route_table_id = aws_route_table.firewall_private.id
}

# Transit Gateway VPC Attachment for Firewall VPC
resource "aws_ec2_transit_gateway_vpc_attachment" "firewall" {
  subnet_ids         = aws_subnet.firewall_private[*].id
  transit_gateway_id = aws_ec2_transit_gateway.main.id
  vpc_id             = aws_vpc.firewall.id

  tags = merge(
    var.common_tags,
    {
      Name = "${var.name_prefix}-tgw-attachment-firewall"
    }
  )
}

# Network Firewall
resource "aws_networkfirewall_firewall" "main" {
  name                = "${var.name_prefix}-network-firewall"
  firewall_policy_arn = aws_networkfirewall_firewall_policy.main.arn
  vpc_id              = aws_vpc.firewall.id

  dynamic "subnet_mapping" {
    for_each = aws_subnet.firewall_public
    content {
      subnet_id = subnet_mapping.value.id
    }
  }

  tags = merge(
    var.common_tags,
    {
      Name = "${var.name_prefix}-network-firewall"
    }
  )
}

# Network Firewall Policy
resource "aws_networkfirewall_firewall_policy" "main" {
  name = "${var.name_prefix}-firewall-policy"

  firewall_policy {
    stateless_default_actions          = var.firewall_policy_stateless_default_actions
    stateless_fragment_default_actions = var.firewall_policy_stateless_fragment_default_actions

    stateful_rule_group_reference {
      resource_arn = aws_networkfirewall_rule_group.stateless.arn
    }

    stateful_rule_group_reference {
      resource_arn = aws_networkfirewall_rule_group.stateful.arn
    }
  }

  tags = merge(
    var.common_tags,
    {
      Name = "${var.name_prefix}-firewall-policy"
    }
  )
}

# Stateless Rule Group
resource "aws_networkfirewall_rule_group" "stateless" {
  capacity = var.stateless_rule_capacity
  name     = "${var.name_prefix}-stateless-rules"
  type     = "STATELESS"
  rule_group {
    rules_source {
      stateless_rules_and_custom_actions {
        stateless_rule {
          priority = 1
          rule_definition {
            actions = ["aws:forward_to_sfe"]
            match_attributes {
              destination {
                address_definition = "0.0.0.0/0"
              }
              source {
                address_definition = "0.0.0.0/0"
              }
            }
          }
        }
      }
    }
  }

  tags = merge(
    var.common_tags,
    {
      Name = "${var.name_prefix}-stateless-rules"
    }
  )
}

# Stateful Rule Group
resource "aws_networkfirewall_rule_group" "stateful" {
  capacity = var.stateful_rule_capacity
  name     = "${var.name_prefix}-stateful-rules"
  type     = "STATEFUL"
  rule_group {
    rules_source {
      rules_source_list {
        generated_rules_type = "DENYLIST"
        target_types         = ["HTTP_HOST", "TLS_SNI"]
        targets              = var.blocked_domains
      }
    }
  }

  tags = merge(
    var.common_tags,
    {
      Name = "${var.name_prefix}-stateful-rules"
    }
  )
}

# Network Firewall Logging Configuration
resource "aws_networkfirewall_logging_configuration" "main" {
  count       = var.enable_network_firewall_logging ? 1 : 0
  firewall_arn = aws_networkfirewall_firewall.main.arn

  logging_configuration {
    dynamic "log_destination_config" {
      for_each = var.enable_s3_logging ? [1] : []
      content {
        log_destination = {
          bucketName = aws_s3_bucket.firewall_logs[0].bucket
          prefix      = "firewall-logs/"
        }
        log_destination_type = "S3"
        log_type             = "FLOW"
      }
    }

    dynamic "log_destination_config" {
      for_each = var.enable_s3_logging ? [1] : []
      content {
        log_destination = {
          bucketName = aws_s3_bucket.firewall_logs[0].bucket
          prefix      = "alert-logs/"
        }
        log_destination_type = "S3"
        log_type             = "ALERT"
      }
    }

    dynamic "log_destination_config" {
      for_each = var.enable_cloudwatch_logging ? [1] : []
      content {
        log_destination = {
          logGroup = aws_cloudwatch_log_group.firewall[0].name
        }
        log_destination_type = "CloudWatch"
        log_type             = "FLOW"
      }
    }

    dynamic "log_destination_config" {
      for_each = var.enable_cloudwatch_logging ? [1] : []
      content {
        log_destination = {
          logGroup = aws_cloudwatch_log_group.firewall[0].name
        }
        log_destination_type = "CloudWatch"
        log_type             = "ALERT"
      }
    }
  }
}

# S3 Bucket for Firewall Logs
resource "aws_s3_bucket" "firewall_logs" {
  count  = var.enable_s3_logging ? 1 : 0
  bucket = "${var.name_prefix}-firewall-logs-${random_string.bucket_suffix.result}"

  tags = merge(
    var.common_tags,
    {
      Name = "${var.name_prefix}-firewall-logs"
    }
  )
}

resource "aws_s3_bucket_versioning" "firewall_logs" {
  count  = var.enable_s3_logging ? 1 : 0
  bucket = aws_s3_bucket.firewall_logs[0].id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "firewall_logs" {
  count  = var.enable_s3_logging ? 1 : 0
  bucket = aws_s3_bucket.firewall_logs[0].id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = var.s3_bucket_encryption
    }
  }
}

resource "aws_s3_bucket_public_access_block" "firewall_logs" {
  count  = var.enable_s3_logging ? 1 : 0
  bucket = aws_s3_bucket.firewall_logs[0].id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Random string for unique bucket names
resource "random_string" "bucket_suffix" {
  length  = 8
  special = false
  upper   = false
}

# CloudWatch Log Group for Firewall Logs
resource "aws_cloudwatch_log_group" "firewall" {
  count             = var.enable_cloudwatch_logging ? 1 : 0
  name              = "/aws/networkfirewall/${var.name_prefix}"
  retention_in_days = var.log_retention_days

  tags = merge(
    var.common_tags,
    {
      Name = "${var.name_prefix}-firewall-logs"
    }
  )
}

# IAM Role for Network Firewall
resource "aws_iam_role" "firewall" {
  name = "${var.name_prefix}-network-firewall-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "network-firewall.amazonaws.com"
        }
      }
    ]
  })

  tags = merge(
    var.common_tags,
    {
      Name = "${var.name_prefix}-network-firewall-role"
    }
  )
}

resource "aws_iam_role_policy" "firewall" {
  name = "${var.name_prefix}-network-firewall-policy"
  role = aws_iam_role.firewall.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = concat(
      var.enable_cloudwatch_logging ? [
        {
          Effect = "Allow"
          Action = [
            "logs:CreateLogGroup",
            "logs:CreateLogStream",
            "logs:PutLogEvents",
            "logs:DescribeLogGroups",
            "logs:DescribeLogStreams"
          ]
          Resource = "${aws_cloudwatch_log_group.firewall[0].arn}:*"
        }
      ] : [],
      var.enable_s3_logging ? [
        {
          Effect = "Allow"
          Action = [
            "s3:PutObject",
            "s3:GetObject",
            "s3:ListBucket"
          ]
          Resource = [
            aws_s3_bucket.firewall_logs[0].arn,
            "${aws_s3_bucket.firewall_logs[0].arn}/*"
          ]
        }
      ] : []
    )
  })
}

# Security Groups
resource "aws_security_group" "firewall" {
  name_prefix = "${var.name_prefix}-firewall-"
  vpc_id      = aws_vpc.firewall.id

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = merge(
    var.common_tags,
    {
      Name = "${var.name_prefix}-firewall-sg"
    }
  )
}

# VPC Endpoints for Network Firewall
resource "aws_vpc_endpoint" "firewall" {
  count             = length(var.vpc_endpoint_services)
  vpc_id            = aws_vpc.firewall.id
  service_name      = var.vpc_endpoint_services[count.index]
  vpc_endpoint_type = "Interface"
  subnet_ids        = aws_subnet.firewall_private[*].id

  security_group_ids = [aws_security_group.firewall.id]

  private_dns_enabled = true

  tags = merge(
    var.common_tags,
    {
      Name = "${var.name_prefix}-endpoint-${count.index + 1}"
    }
  )
} 