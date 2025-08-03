# =============================================================================
# Basic Example: Network Firewall with Transit Gateway
# Enhanced with comprehensive customization options
# =============================================================================

terraform {
  required_version = ">= 1.0"
  
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = "us-east-1"
}

# ==============================================================================
# Required Configuration
# ==============================================================================

module "network_firewall" {
  source = "../../"

  # Basic Configuration
  name_prefix = "basic-firewall"
  
  # Availability Zones - Minimum 2 required for high availability
  availability_zones = ["us-east-1a", "us-east-1b"]
  
  # VPC Configuration
  firewall_vpc_cidr = "10.100.0.0/16"
  firewall_public_subnets  = ["10.100.1.0/24", "10.100.2.0/24"]
  firewall_private_subnets = ["10.100.10.0/24", "10.100.11.0/24"]
  
  # Enable DNS support for VPC
  enable_dns_hostnames = true
  enable_dns_support   = true
  
  # ==============================================================================
  # Transit Gateway Configuration
  # ==============================================================================
  
  # Transit Gateway ASN (Private range: 64512-65534)
  transit_gateway_asn = 64512
  
  # Transit Gateway features
  transit_gateway_auto_accept_shared_attachments = "disable"
  transit_gateway_default_route_table_association = "enable"
  transit_gateway_default_route_table_propagation = "enable"
  transit_gateway_dns_support = "enable"
  transit_gateway_vpn_ecmp_support = "enable"
  transit_gateway_multicast_support = "disable"
  
  # VPC Attachment Configuration
  transit_gateway_appliance_mode_support = "disable"
  transit_gateway_ipv6_support = "disable"
  
  # ==============================================================================
  # Network Firewall Configuration
  # ==============================================================================
  
  # Firewall Protection Settings
  firewall_delete_protection = false
  firewall_policy_change_protection = false
  firewall_subnet_change_protection = false
  
  # Rule Group Configuration
  enable_stateless_rules = true
  enable_stateful_rules = true
  enable_stateful_engine_options = false
  
  # Rule Priorities
  stateless_rule_priority = 1
  stateful_rule_priority = 2
  
  # Stateful Rule Order
  stateful_rule_order = "DEFAULT_ACTION_ORDER"
  
  # Stateless Rule Configuration
  stateless_rule_actions = ["aws:forward_to_sfe"]
  stateless_rule_destination_cidr = "0.0.0.0/0"
  stateless_rule_source_cidr = "0.0.0.0/0"
  stateless_rule_protocols = [1, 6, 17] # ICMP, TCP, UDP
  
  # Stateful Rule Configuration
  stateful_rules_generated_type = "DENYLIST"
  stateful_rules_target_types = ["HTTP_HOST", "TLS_SNI"]
  
  # Domain Blocking
  blocked_domains = [
    "malware.example.com",
    "phishing.example.com",
    "suspicious-site.com"
  ]
  
  # Firewall Policy Configuration
  firewall_policy_stateless_default_actions = ["aws:forward_to_sfe"]
  firewall_policy_stateless_fragment_default_actions = ["aws:forward_to_sfe"]
  
  # Rule Group Capacities
  stateless_rule_capacity = 100
  stateful_rule_capacity = 100
  
  # ==============================================================================
  # Logging Configuration
  # ==============================================================================
  
  # Enable logging features
  enable_network_firewall_logging = true
  enable_s3_logging = true
  enable_cloudwatch_logging = true
  
  # Log retention
  log_retention_days = 30
  
  # S3 Logging Configuration
  s3_log_prefix = "firewall-logs/"
  s3_alert_log_prefix = "alert-logs/"
  
  # S3 Bucket Configuration
  s3_bucket_encryption = "AES256"
  s3_bucket_force_destroy = false
  s3_bucket_versioning_status = "Enabled"
  s3_bucket_key_enabled = true
  
  # S3 Public Access Block
  s3_block_public_acls = true
  s3_block_public_policy = true
  s3_ignore_public_acls = true
  s3_restrict_public_buckets = true
  
  # S3 Lifecycle Configuration
  enable_s3_lifecycle = false
  s3_transition_to_ia_days = 0
  s3_transition_to_glacier_days = 0
  s3_expiration_days = 2555 # 7 years
  s3_abort_incomplete_multipart_upload_days = 7
  
  # S3 Bucket Suffix Configuration
  bucket_suffix_length = 8
  bucket_suffix_special = false
  bucket_suffix_upper = false
  bucket_suffix_lower = true
  bucket_suffix_numeric = true
  
  # CloudWatch Configuration
  cloudwatch_kms_key_id = null
  enable_metric_filters = false
  cloudwatch_alert_pattern = "[timestamp, action=BLOCK, ...]"
  
  # ==============================================================================
  # IAM Configuration
  # ==============================================================================
  
  iam_role_path = "/"
  enable_advanced_permissions = false
  
  # ==============================================================================
  # Security Groups Configuration
  # ==============================================================================
  
  # Firewall Security Group
  firewall_security_group_egress_cidrs = ["0.0.0.0/0"]
  firewall_security_group_ingress_rules = []
  
  # ==============================================================================
  # VPC Endpoints Configuration
  # ==============================================================================
  
  vpc_endpoint_services = [
    "com.amazonaws.us-east-1.logs",
    "com.amazonaws.us-east-1.s3"
  ]
  vpc_endpoint_private_dns_enabled = true
  vpc_endpoint_ip_address_type = "ipv4"
  
  # ==============================================================================
  # VPC Flow Logs Configuration
  # ==============================================================================
  
  enable_flow_logs = true
  flow_logs_traffic_type = "ALL"
  flow_logs_retention_days = 30
  
  # ==============================================================================
  # Tags and Metadata
  # ==============================================================================
  
  common_tags = {
    Environment = "development"
    Project     = "network-security"
    Owner       = "security-team"
    CostCenter  = "security"
    Component   = "network-firewall"
    ManagedBy   = "terraform"
  }
}

# ==============================================================================
# Outputs
# ==============================================================================

# Output important information
output "transit_gateway_id" {
  description = "Transit Gateway ID"
  value       = module.network_firewall.transit_gateway_id
}

output "network_firewall_id" {
  description = "Network Firewall ID"
  value       = module.network_firewall.network_firewall_id
}

output "firewall_vpc_id" {
  description = "Firewall VPC ID"
  value       = module.network_firewall.firewall_vpc_id
}

output "firewall_logs_bucket" {
  description = "S3 bucket for firewall logs"
  value       = module.network_firewall.firewall_logs_s3_bucket
}

output "cloudwatch_log_group" {
  description = "CloudWatch log group for firewall logs"
  value       = module.network_firewall.cloudwatch_log_group_name
}

output "firewall_policy_arn" {
  description = "Network Firewall Policy ARN"
  value       = module.network_firewall.firewall_policy_arn
}

output "stateless_rule_group_arn" {
  description = "Stateless Rule Group ARN"
  value       = module.network_firewall.stateless_rule_group_arn
}

output "stateful_rule_group_arn" {
  description = "Stateful Rule Group ARN"
  value       = module.network_firewall.stateful_rule_group_arn
} 