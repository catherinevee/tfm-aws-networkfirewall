# =============================================================================
# Network Firewall Configuration
# =============================================================================

# AWS Network Firewall resource
resource "aws_networkfirewall_firewall" "main" {
  name                = "${var.name_prefix}-firewall"
  firewall_policy_arn = aws_networkfirewall_firewall_policy.main.arn
  vpc_id             = aws_vpc.firewall.id
  description        = "Network Firewall for centralized traffic inspection"

  dynamic "subnet_mapping" {
    for_each = aws_subnet.firewall_public
    content {
      subnet_id = subnet_mapping.value.id
    }
  }

  tags = merge(
    var.common_tags,
    {
      Name = "${var.name_prefix}-firewall"
      Type = "network-firewall"
      Component = "security"
    }
  )
}

# Firewall Policy
resource "aws_networkfirewall_firewall_policy" "main" {
  name = "${var.name_prefix}-policy"

  firewall_policy {
    stateless_default_actions          = ["aws:forward_to_sfe"]
    stateless_fragment_default_actions = ["aws:forward_to_sfe"]

    dynamic "stateful_rule_group_reference" {
      for_each = var.firewall_config != null ? coalesce(var.firewall_config.stateful_rules, []) : []
      content {
        name     = stateful_rule_group_reference.value.name
        priority = stateful_rule_group_reference.value.priority
      }
    }
  }

  tags = merge(
    var.common_tags,
    {
      Name = "${var.name_prefix}-policy"
      Type = "firewall-policy"
      Component = "security"
    }
  )
}
  
  # Advanced Configuration
  amazon_side_asn = var.transit_gateway_asn # Default: 64512 (Private ASN range)
  
  tags = merge(
    var.common_tags,
    {
      Name = "${var.name_prefix}-tgw"
      Type = "transit-gateway"
      Component = "networking"
    }
  )
}

# Transit Gateway Route Tables - Separate routing for inspection and private traffic
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

# ==============================================================================
# VPC Configuration
# ==============================================================================

# VPC for Network Firewall - Dedicated VPC for firewall infrastructure
resource "aws_vpc" "firewall" {
  cidr_block           = var.firewall_vpc_cidr # Default: "10.100.0.0/16"
  enable_dns_hostnames = var.enable_dns_hostnames # Default: true
  enable_dns_support   = var.enable_dns_support # Default: true

  # Advanced VPC Configuration
  instance_tenancy = var.vpc_instance_tenancy # Default: "default"
  ipv4_ipam_pool_id = var.vpc_ipv4_ipam_pool_id # Optional: Custom IPAM pool
  ipv4_netmask_length = var.vpc_ipv4_netmask_length # Optional: Custom netmask

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

# ==============================================================================
# Subnet Configuration
# ==============================================================================

# Public Subnets for Network Firewall - For internet-facing firewall interfaces
resource "aws_subnet" "firewall_public" {
  count             = length(var.firewall_public_subnets)
  vpc_id            = aws_vpc.firewall.id
  cidr_block        = var.firewall_public_subnets[count.index]
  availability_zone = var.availability_zones[count.index]

  # Advanced Subnet Configuration
  map_public_ip_on_launch = var.firewall_public_subnet_map_public_ip # Default: false
  assign_ipv6_address_on_creation = var.enable_ipv6 # Default: false
  ipv6_cidr_block = var.enable_ipv6 ? var.firewall_public_subnet_ipv6_cidrs[count.index] : null

  tags = merge(
    var.common_tags,
    {
      Name = "${var.name_prefix}-firewall-public-${var.availability_zones[count.index]}"
      Type = "subnet"
      Component = "networking"
      Tier = "Public"
      Purpose = "firewall-public"
    }
  )
}

# Private Subnets for Network Firewall - For internal firewall interfaces
resource "aws_subnet" "firewall_private" {
  count             = length(var.firewall_private_subnets)
  vpc_id            = aws_vpc.firewall.id
  cidr_block        = var.firewall_private_subnets[count.index]
  availability_zone = var.availability_zones[count.index]

  # Advanced Subnet Configuration
  assign_ipv6_address_on_creation = var.enable_ipv6 # Default: false
  ipv6_cidr_block = var.enable_ipv6 ? var.firewall_private_subnet_ipv6_cidrs[count.index] : null

  tags = merge(
    var.common_tags,
    {
      Name = "${var.name_prefix}-firewall-private-${var.availability_zones[count.index]}"
      Type = "subnet"
      Component = "networking"
      Tier = "Private"
      Purpose = "firewall-private"
    }
  )
}

# ==============================================================================
# Internet Gateway Configuration
# ==============================================================================

# Internet Gateway for Firewall VPC - Provides internet connectivity
resource "aws_internet_gateway" "firewall" {
  vpc_id = aws_vpc.firewall.id

  tags = merge(
    var.common_tags,
    {
      Name = "${var.name_prefix}-firewall-igw"
      Type = "internet-gateway"
      Component = "networking"
    }
  )
}

# ==============================================================================
# Route Table Configuration
# ==============================================================================

# Route Table for Public Subnets - Routes traffic to internet gateway
resource "aws_route_table" "firewall_public" {
  vpc_id = aws_vpc.firewall.id

  # Default route to internet gateway
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.firewall.id
  }

  # IPv6 route (if enabled)
  dynamic "route" {
    for_each = var.enable_ipv6 ? [1] : []
    content {
      ipv6_cidr_block = "::/0"
      gateway_id      = aws_internet_gateway.firewall.id
    }
  }

  tags = merge(
    var.common_tags,
    {
      Name = "${var.name_prefix}-firewall-public-rt"
      Type = "route-table"
      Component = "routing"
      Purpose = "public"
    }
  )
}

# Route Table for Private Subnets - Routes traffic through Transit Gateway
resource "aws_route_table" "firewall_private" {
  vpc_id = aws_vpc.firewall.id

  # Route to Transit Gateway for private traffic
  route {
    cidr_block         = "0.0.0.0/0"
    transit_gateway_id = aws_ec2_transit_gateway.main.id
  }

  tags = merge(
    var.common_tags,
    {
      Name = "${var.name_prefix}-firewall-private-rt"
      Type = "route-table"
      Component = "routing"
      Purpose = "private"
    }
  )
}

# Route Table Associations - Associate subnets with appropriate route tables
resource "aws_route_table_association" "firewall_public" {
  count          = length(aws_subnet.firewall_public)
  subnet_id      = aws_subnet.firewall_public[count.index].id
  route_table_id = aws_route_table.firewall_public.id
}

resource "aws_route_table_association" "firewall_private" {
  count          = length(aws_subnet.firewall_private)
  subnet_id      = aws_subnet.firewall_private[count.index].id
  route_table_id = aws_route_table.firewall_private.id
}

# ==============================================================================
# Transit Gateway VPC Attachment Configuration
# ==============================================================================

# Transit Gateway VPC Attachment - Connects firewall VPC to Transit Gateway
resource "aws_ec2_transit_gateway_vpc_attachment" "firewall" {
  subnet_ids         = aws_subnet.firewall_private[*].id
  transit_gateway_id = aws_ec2_transit_gateway.main.id
  vpc_id             = aws_vpc.firewall.id

  # Advanced Attachment Configuration
  appliance_mode_support = var.transit_gateway_appliance_mode_support # Default: "disable"
  dns_support            = var.transit_gateway_dns_support # Default: "enable"
  ipv6_support           = var.transit_gateway_ipv6_support # Default: "disable"

  tags = merge(
    var.common_tags,
    {
      Name = "${var.name_prefix}-tgw-attachment-firewall"
      Type = "transit-gateway-vpc-attachment"
      Component = "connectivity"
    }
  )
}

# ==============================================================================
# Network Firewall Configuration
# ==============================================================================

# Network Firewall - AWS managed firewall service
resource "aws_networkfirewall_firewall" "main" {
  name                = "${var.name_prefix}-network-firewall"
  firewall_policy_arn = aws_networkfirewall_firewall_policy.main.arn
  vpc_id              = aws_vpc.firewall.id

  # Subnet mapping for firewall endpoints
  dynamic "subnet_mapping" {
    for_each = aws_subnet.firewall_public
    content {
      subnet_id = subnet_mapping.value.id
    }
  }

  # Advanced Firewall Configuration
  delete_protection = var.firewall_delete_protection # Default: false
  firewall_policy_change_protection = var.firewall_policy_change_protection # Default: false
  subnet_change_protection = var.firewall_subnet_change_protection # Default: false

  tags = merge(
    var.common_tags,
    {
      Name = "${var.name_prefix}-network-firewall"
      Type = "network-firewall"
      Component = "security"
    }
  )
}

# ==============================================================================
# Network Firewall Policy Configuration
# ==============================================================================

# Network Firewall Policy - Defines firewall behavior and rules
resource "aws_networkfirewall_firewall_policy" "main" {
  name = "${var.name_prefix}-firewall-policy"

  firewall_policy {
    # Stateless traffic handling
    stateless_default_actions          = var.firewall_policy_stateless_default_actions # Default: ["aws:forward_to_sfe"]
    stateless_fragment_default_actions = var.firewall_policy_stateless_fragment_default_actions # Default: ["aws:forward_to_sfe"]

    # Stateful rule group references
    dynamic "stateful_rule_group_reference" {
      for_each = var.enable_stateless_rules ? [1] : []
      content {
        resource_arn = aws_networkfirewall_rule_group.stateless.arn
        priority     = var.stateless_rule_priority # Default: 1
      }
    }

    dynamic "stateful_rule_group_reference" {
      for_each = var.enable_stateful_rules ? [1] : []
      content {
        resource_arn = aws_networkfirewall_rule_group.stateful.arn
        priority     = var.stateful_rule_priority # Default: 2
      }
    }

    # Custom action definitions
    dynamic "stateful_engine_options" {
      for_each = var.enable_stateful_engine_options ? [1] : []
      content {
        rule_order = var.stateful_rule_order # Default: "DEFAULT_ACTION_ORDER"
      }
    }
  }

  tags = merge(
    var.common_tags,
    {
      Name = "${var.name_prefix}-firewall-policy"
      Type = "network-firewall-policy"
      Component = "security"
    }
  )
}

# ==============================================================================
# Network Firewall Rule Groups Configuration
# ==============================================================================

# Stateless Rule Group - For stateless traffic inspection
resource "aws_networkfirewall_rule_group" "stateless" {
  count    = var.enable_stateless_rules ? 1 : 0
  capacity = var.stateless_rule_capacity # Default: 100
  name     = "${var.name_prefix}-stateless-rules"
  type     = "STATELESS"
  
  rule_group {
    rules_source {
      stateless_rules_and_custom_actions {
        # Default stateless rule - forward all traffic to stateful engine
        stateless_rule {
          priority = var.stateless_rule_priority # Default: 1
          rule_definition {
            actions = var.stateless_rule_actions # Default: ["aws:forward_to_sfe"]
            match_attributes {
              destination {
                address_definition = var.stateless_rule_destination_cidr # Default: "0.0.0.0/0"
              }
              source {
                address_definition = var.stateless_rule_source_cidr # Default: "0.0.0.0/0"
              }
              protocols = var.stateless_rule_protocols # Default: [1, 6, 17] (ICMP, TCP, UDP)
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
      Type = "network-firewall-rule-group"
      Component = "security"
      RuleType = "stateless"
    }
  )
}

# Stateful Rule Group - For stateful traffic inspection and domain blocking
resource "aws_networkfirewall_rule_group" "stateful" {
  count    = var.enable_stateful_rules ? 1 : 0
  capacity = var.stateful_rule_capacity # Default: 100
  name     = "${var.name_prefix}-stateful-rules"
  type     = "STATEFUL"
  
  rule_group {
    rules_source {
      rules_source_list {
        generated_rules_type = var.stateful_rules_generated_type # Default: "DENYLIST"
        target_types         = var.stateful_rules_target_types # Default: ["HTTP_HOST", "TLS_SNI"]
        targets              = var.blocked_domains # List of domains to block
      }
    }
  }

  tags = merge(
    var.common_tags,
    {
      Name = "${var.name_prefix}-stateful-rules"
      Type = "network-firewall-rule-group"
      Component = "security"
      RuleType = "stateful"
    }
  )
}

# ==============================================================================
# Network Firewall Logging Configuration
# ==============================================================================

# Network Firewall Logging Configuration - Configures logging destinations
resource "aws_networkfirewall_logging_configuration" "main" {
  count       = var.enable_network_firewall_logging ? 1 : 0
  firewall_arn = aws_networkfirewall_firewall.main.arn

  logging_configuration {
    # S3 Logging Configuration
    dynamic "log_destination_config" {
      for_each = var.enable_s3_logging ? [1] : []
      content {
        log_destination = {
          bucketName = aws_s3_bucket.firewall_logs[0].bucket
          prefix      = var.s3_log_prefix # Default: "firewall-logs/"
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
          prefix      = var.s3_alert_log_prefix # Default: "alert-logs/"
        }
        log_destination_type = "S3"
        log_type             = "ALERT"
      }
    }

    # CloudWatch Logging Configuration
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

# ==============================================================================
# S3 Bucket Configuration for Logging
# ==============================================================================

# S3 Bucket for Firewall Logs - Secure storage for firewall logs
resource "aws_s3_bucket" "firewall_logs" {
  count  = var.enable_s3_logging ? 1 : 0
  bucket = "${var.name_prefix}-firewall-logs-${random_string.bucket_suffix.result}"

  # Advanced S3 Configuration
  force_destroy = var.s3_bucket_force_destroy # Default: false

  tags = merge(
    var.common_tags,
    {
      Name = "${var.name_prefix}-firewall-logs"
      Type = "s3-bucket"
      Component = "storage"
      Purpose = "firewall-logs"
    }
  )
}

# S3 Bucket Versioning - Enables versioning for data protection
resource "aws_s3_bucket_versioning" "firewall_logs" {
  count  = var.enable_s3_logging ? 1 : 0
  bucket = aws_s3_bucket.firewall_logs[0].id
  versioning_configuration {
    status = var.s3_bucket_versioning_status # Default: "Enabled"
  }
}

# S3 Bucket Server-Side Encryption - Encrypts data at rest
resource "aws_s3_bucket_server_side_encryption_configuration" "firewall_logs" {
  count  = var.enable_s3_logging ? 1 : 0
  bucket = aws_s3_bucket.firewall_logs[0].id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = var.s3_bucket_encryption # Default: "AES256"
      kms_master_key_id = var.s3_bucket_encryption == "aws:kms" ? var.s3_bucket_kms_key_id : null
    }
    bucket_key_enabled = var.s3_bucket_key_enabled # Default: true
  }
}

# S3 Bucket Public Access Block - Prevents public access
resource "aws_s3_bucket_public_access_block" "firewall_logs" {
  count  = var.enable_s3_logging ? 1 : 0
  bucket = aws_s3_bucket.firewall_logs[0].id

  block_public_acls       = var.s3_block_public_acls # Default: true
  block_public_policy     = var.s3_block_public_policy # Default: true
  ignore_public_acls      = var.s3_ignore_public_acls # Default: true
  restrict_public_buckets = var.s3_restrict_public_buckets # Default: true
}

# S3 Bucket Lifecycle Configuration - Manages log retention
resource "aws_s3_bucket_lifecycle_configuration" "firewall_logs" {
  count  = var.enable_s3_logging && var.enable_s3_lifecycle ? 1 : 0
  bucket = aws_s3_bucket.firewall_logs[0].id

  rule {
    id     = "firewall-logs-lifecycle"
    status = "Enabled"

    # Transition to IA after specified days
    dynamic "transition" {
      for_each = var.s3_transition_to_ia_days > 0 ? [1] : []
      content {
        days          = var.s3_transition_to_ia_days
        storage_class = "STANDARD_IA"
      }
    }

    # Transition to Glacier after specified days
    dynamic "transition" {
      for_each = var.s3_transition_to_glacier_days > 0 ? [1] : []
      content {
        days          = var.s3_transition_to_glacier_days
        storage_class = "GLACIER"
      }
    }

    # Expire objects after specified days
    expiration {
      days = var.s3_expiration_days # Default: 2555 (7 years)
    }

    # Abort incomplete multipart uploads
    abort_incomplete_multipart_upload {
      days_after_initiation = var.s3_abort_incomplete_multipart_upload_days # Default: 7
    }
  }
}

# Random string for unique bucket names
resource "random_string" "bucket_suffix" {
  length  = var.bucket_suffix_length # Default: 8
  special = var.bucket_suffix_special # Default: false
  upper   = var.bucket_suffix_upper # Default: false
  lower   = var.bucket_suffix_lower # Default: true
  numeric = var.bucket_suffix_numeric # Default: true
}

# ==============================================================================
# CloudWatch Configuration
# ==============================================================================

# CloudWatch Log Group for Firewall Logs - Centralized log management
resource "aws_cloudwatch_log_group" "firewall" {
  count             = var.enable_cloudwatch_logging ? 1 : 0
  name              = "/aws/networkfirewall/${var.name_prefix}"
  retention_in_days = var.log_retention_days # Default: 30

  # Advanced CloudWatch Configuration
  kms_key_id = var.cloudwatch_kms_key_id # Optional: Custom KMS key

  tags = merge(
    var.common_tags,
    {
      Name = "${var.name_prefix}-firewall-logs"
      Type = "cloudwatch-log-group"
      Component = "monitoring"
    }
  )
}

# CloudWatch Metric Filters - For log analysis and alerting
resource "aws_cloudwatch_log_metric_filter" "firewall_alerts" {
  count = var.enable_cloudwatch_logging && var.enable_metric_filters ? 1 : 0

  name           = "${var.name_prefix}-firewall-alerts"
  pattern        = var.cloudwatch_alert_pattern # Default: "[timestamp, action=BLOCK, ...]"
  log_group_name = aws_cloudwatch_log_group.firewall[0].name

  metric_transformation {
    name      = "FirewallBlocks"
    namespace = "NetworkFirewall"
    value     = "1"
  }
}

# ==============================================================================
# IAM Configuration
# ==============================================================================

# IAM Role for Network Firewall - Allows firewall to access AWS services
resource "aws_iam_role" "firewall" {
  name = "${var.name_prefix}-network-firewall-role"

  # Trust policy for Network Firewall service
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

  # Advanced IAM Configuration
  path = var.iam_role_path # Default: "/"
  description = "IAM role for Network Firewall service"

  tags = merge(
    var.common_tags,
    {
      Name = "${var.name_prefix}-network-firewall-role"
      Type = "iam-role"
      Component = "security"
    }
  )
}

# IAM Policy for Network Firewall - Permissions for logging and monitoring
resource "aws_iam_role_policy" "firewall" {
  name = "${var.name_prefix}-network-firewall-policy"
  role = aws_iam_role.firewall.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = concat(
      # CloudWatch Logging Permissions
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
      # S3 Logging Permissions
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
      ] : [],
      # Additional permissions for advanced features
      var.enable_advanced_permissions ? [
        {
          Effect = "Allow"
          Action = [
            "ec2:DescribeVpcs",
            "ec2:DescribeSubnets",
            "ec2:DescribeSecurityGroups"
          ]
          Resource = "*"
        }
      ] : []
    )
  })
}

# ==============================================================================
# Security Groups Configuration
# ==============================================================================

# Security Group for Network Firewall - Controls network access
resource "aws_security_group" "firewall" {
  name_prefix = "${var.name_prefix}-firewall-"
  vpc_id      = aws_vpc.firewall.id
  description = "Security group for Network Firewall"

  # Egress rule - allow all outbound traffic
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = var.firewall_security_group_egress_cidrs # Default: ["0.0.0.0/0"]
    description = "Allow all outbound traffic"
  }

  # Ingress rules - configurable based on requirements
  dynamic "ingress" {
    for_each = var.firewall_security_group_ingress_rules
    content {
      from_port   = ingress.value.from_port
      to_port     = ingress.value.to_port
      protocol    = ingress.value.protocol
      cidr_blocks = ingress.value.cidr_blocks
      description = ingress.value.description
    }
  }

  tags = merge(
    var.common_tags,
    {
      Name = "${var.name_prefix}-firewall-sg"
      Type = "security-group"
      Component = "security"
    }
  )
}

# ==============================================================================
# VPC Endpoints Configuration
# ==============================================================================

# VPC Endpoints for Network Firewall - Private connectivity to AWS services
resource "aws_vpc_endpoint" "firewall" {
  count             = length(var.vpc_endpoint_services)
  vpc_id            = aws_vpc.firewall.id
  service_name      = var.vpc_endpoint_services[count.index]
  vpc_endpoint_type = "Interface"
  subnet_ids        = aws_subnet.firewall_private[*].id

  # Advanced VPC Endpoint Configuration
  security_group_ids = [aws_security_group.firewall.id]
  private_dns_enabled = var.vpc_endpoint_private_dns_enabled # Default: true
  ip_address_type = var.vpc_endpoint_ip_address_type # Default: "ipv4"

  tags = merge(
    var.common_tags,
    {
      Name = "${var.name_prefix}-endpoint-${count.index + 1}"
      Type = "vpc-endpoint"
      Component = "connectivity"
      Service = var.vpc_endpoint_services[count.index]
    }
  )
}

# ==============================================================================
# VPC Flow Logs Configuration
# ==============================================================================

# VPC Flow Logs - Network traffic monitoring
resource "aws_flow_log" "firewall_vpc" {
  count = var.enable_flow_logs ? 1 : 0

  vpc_id         = aws_vpc.firewall.id
  traffic_type   = var.flow_logs_traffic_type # Default: "ALL"
  iam_role_arn   = aws_iam_role.flow_logs[0].arn
  log_destination = aws_cloudwatch_log_group.flow_logs[0].arn

  tags = merge(
    var.common_tags,
    {
      Name = "${var.name_prefix}-flow-logs"
      Type = "flow-log"
      Component = "monitoring"
    }
  )
}

# CloudWatch Log Group for VPC Flow Logs
resource "aws_cloudwatch_log_group" "flow_logs" {
  count             = var.enable_flow_logs ? 1 : 0
  name              = "/aws/vpc/flowlogs/${var.name_prefix}"
  retention_in_days = var.flow_logs_retention_days # Default: 30

  tags = merge(
    var.common_tags,
    {
      Name = "${var.name_prefix}-flow-logs"
      Type = "cloudwatch-log-group"
      Component = "monitoring"
    }
  )
}

# IAM Role for VPC Flow Logs
resource "aws_iam_role" "flow_logs" {
  count = var.enable_flow_logs ? 1 : 0

  name = "${var.name_prefix}-flow-logs-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "vpc-flow-logs.amazonaws.com"
        }
      }
    ]
  })

  tags = merge(
    var.common_tags,
    {
      Name = "${var.name_prefix}-flow-logs-role"
      Type = "iam-role"
      Component = "monitoring"
    }
  )
}

# IAM Policy for VPC Flow Logs
resource "aws_iam_role_policy" "flow_logs" {
  count = var.enable_flow_logs ? 1 : 0

  name = "${var.name_prefix}-flow-logs-policy"
  role = aws_iam_role.flow_logs[0].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents",
          "logs:DescribeLogGroups",
          "logs:DescribeLogStreams"
        ]
        Resource = "${aws_cloudwatch_log_group.flow_logs[0].arn}:*"
      }
    ]
  })
} 