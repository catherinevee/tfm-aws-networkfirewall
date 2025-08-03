# =============================================================================
# Advanced Example: Enterprise Network Firewall with Transit Gateway
# Enhanced with comprehensive customization options for enterprise deployments
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
# Data Sources
# ==============================================================================

# Get available subnets for reference
data "aws_subnets" "public" {
  filter {
    name   = "vpc-id"
    values = [var.vpc_id]
  }
  
  filter {
    name   = "tag:Tier"
    values = ["Public"]
  }
}

# ==============================================================================
# Enterprise Configuration Maps
# ==============================================================================

locals {
  # Enterprise feature configuration
  enterprise_config = {
    enable_high_availability = true
    enable_multi_az_deployment = true
    enable_advanced_monitoring = true
    enable_compliance_features = true
    enable_security_enhancements = true
  }
  
  # Monitoring configuration
  monitoring_config = {
    enable_detailed_logging = true
    enable_metric_filters = true
    enable_anomaly_detection = true
    enable_alerting = true
    enable_retention_policies = true
  }
  
  # Security configuration
  security_config = {
    enable_strict_rules = true
    enable_domain_filtering = true
    enable_protocol_filtering = true
    enable_geo_blocking = false
    enable_threat_intelligence = true
  }
}

# ==============================================================================
# Enterprise Network Firewall Module
# ==============================================================================

module "enterprise_network_firewall" {
  source = "../../"

  # ==============================================================================
  # Basic Configuration - Enterprise Settings
  # ==============================================================================
  
  name_prefix = "enterprise-firewall"
  
  # Multi-AZ deployment for high availability
  availability_zones = ["us-east-1a", "us-east-1b", "us-east-1c"]
  
  # Enterprise VPC Configuration
  firewall_vpc_cidr = "10.200.0.0/16"
  firewall_public_subnets  = ["10.200.1.0/24", "10.200.2.0/24", "10.200.3.0/24"]
  firewall_private_subnets = ["10.200.10.0/24", "10.200.11.0/24", "10.200.12.0/24"]
  
  # Advanced VPC Configuration
  enable_dns_hostnames = true
  enable_dns_support   = true
  vpc_instance_tenancy = "default"
  
  # IPv6 Support (if required)
  enable_ipv6 = var.enable_ipv6
  firewall_public_subnet_ipv6_cidrs = var.enable_ipv6 ? [
    "2001:db8:2000:1::/64",
    "2001:db8:2000:2::/64", 
    "2001:db8:2000:3::/64"
  ] : []
  firewall_private_subnet_ipv6_cidrs = var.enable_ipv6 ? [
    "2001:db8:2000:10::/64",
    "2001:db8:2000:11::/64",
    "2001:db8:2000:12::/64"
  ] : []
  
  # ==============================================================================
  # Transit Gateway Configuration - Enterprise Settings
  # ==============================================================================
  
  # Enterprise ASN configuration
  transit_gateway_asn = 64513 # Enterprise-specific ASN
  
  # Advanced Transit Gateway features
  transit_gateway_auto_accept_shared_attachments = "disable"
  transit_gateway_default_route_table_association = "enable"
  transit_gateway_default_route_table_propagation = "enable"
  transit_gateway_dns_support = "enable"
  transit_gateway_vpn_ecmp_support = "enable"
  transit_gateway_multicast_support = var.enable_multicast ? "enable" : "disable"
  
  # Advanced VPC Attachment Configuration
  transit_gateway_appliance_mode_support = var.enable_appliance_mode ? "enable" : "disable"
  transit_gateway_ipv6_support = var.enable_ipv6 ? "enable" : "disable"
  
  # ==============================================================================
  # Network Firewall Configuration - Enterprise Security
  # ==============================================================================
  
  # Enterprise Protection Settings
  firewall_delete_protection = true
  firewall_policy_change_protection = true
  firewall_subnet_change_protection = true
  
  # Advanced Rule Group Configuration
  enable_stateless_rules = true
  enable_stateful_rules = true
  enable_stateful_engine_options = true
  
  # Enterprise Rule Priorities
  stateless_rule_priority = 1
  stateful_rule_priority = 2
  
  # Strict Rule Order for compliance
  stateful_rule_order = "STRICT_ORDER"
  
  # Advanced Stateless Rule Configuration
  stateless_rule_actions = ["aws:forward_to_sfe"]
  stateless_rule_destination_cidr = "0.0.0.0/0"
  stateless_rule_source_cidr = "0.0.0.0/0"
  stateless_rule_protocols = [1, 6, 17, 58] # ICMP, TCP, UDP, ICMPv6
  
  # Enterprise Stateful Rule Configuration
  stateful_rules_generated_type = "DENYLIST"
  stateful_rules_target_types = ["HTTP_HOST", "TLS_SNI", "HTTP_URI"]
  
  # Comprehensive Domain Blocking
  blocked_domains = concat([
    # Malware domains
    "malware.example.com",
    "phishing.example.com",
    "suspicious-site.com",
    "malicious-domain.net",
    
    # Social media (if required by policy)
    "facebook.com",
    "twitter.com",
    "instagram.com",
    
    # Gaming sites (if required by policy)
    "steam.com",
    "battle.net",
    "origin.com",
    
    # File sharing (if required by policy)
    "thepiratebay.org",
    "kickass.to",
    "rarbg.to"
  ], var.additional_blocked_domains)
  
  # Enterprise Firewall Policy Configuration
  firewall_policy_stateless_default_actions = ["aws:forward_to_sfe"]
  firewall_policy_stateless_fragment_default_actions = ["aws:forward_to_sfe"]
  
  # High Capacity Rule Groups for enterprise workloads
  stateless_rule_capacity = 1000
  stateful_rule_capacity = 1000
  
  # ==============================================================================
  # Advanced Logging Configuration - Enterprise Monitoring
  # ==============================================================================
  
  # Comprehensive logging
  enable_network_firewall_logging = true
  enable_s3_logging = true
  enable_cloudwatch_logging = true
  
  # Extended log retention for compliance
  log_retention_days = 2555 # 7 years for compliance
  
  # Enterprise S3 Logging Configuration
  s3_log_prefix = "enterprise/firewall-logs/"
  s3_alert_log_prefix = "enterprise/alert-logs/"
  
  # Enterprise S3 Bucket Configuration
  s3_bucket_encryption = var.enable_kms_encryption ? "aws:kms" : "AES256"
  s3_bucket_kms_key_id = var.enable_kms_encryption ? var.kms_key_id : null
  s3_bucket_force_destroy = false
  s3_bucket_versioning_status = "Enabled"
  s3_bucket_key_enabled = true
  
  # Strict S3 Public Access Block
  s3_block_public_acls = true
  s3_block_public_policy = true
  s3_ignore_public_acls = true
  s3_restrict_public_buckets = true
  
  # Enterprise S3 Lifecycle Configuration
  enable_s3_lifecycle = true
  s3_transition_to_ia_days = 30
  s3_transition_to_glacier_days = 90
  s3_expiration_days = 2555 # 7 years
  s3_abort_incomplete_multipart_upload_days = 7
  
  # Enterprise S3 Bucket Suffix Configuration
  bucket_suffix_length = 12
  bucket_suffix_special = false
  bucket_suffix_upper = false
  bucket_suffix_lower = true
  bucket_suffix_numeric = true
  
  # Enterprise CloudWatch Configuration
  cloudwatch_kms_key_id = var.enable_kms_encryption ? var.kms_key_id : null
  enable_metric_filters = true
  cloudwatch_alert_pattern = "[timestamp, action=BLOCK, srcaddr, dstaddr, srcport, dstport, protocol, ...]"
  
  # ==============================================================================
  # Enterprise IAM Configuration
  # ==============================================================================
  
  iam_role_path = "/enterprise/"
  enable_advanced_permissions = true
  
  # ==============================================================================
  # Enterprise Security Groups Configuration
  # ==============================================================================
  
  # Restrictive Firewall Security Group
  firewall_security_group_egress_cidrs = ["0.0.0.0/0"]
  firewall_security_group_ingress_rules = [
    {
      from_port   = 443
      to_port     = 443
      protocol    = "tcp"
      cidr_blocks = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
      description = "HTTPS access from private networks"
    },
    {
      from_port   = 80
      to_port     = 80
      protocol    = "tcp"
      cidr_blocks = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
      description = "HTTP access from private networks"
    }
  ]
  
  # ==============================================================================
  # Enterprise VPC Endpoints Configuration
  # ==============================================================================
  
  vpc_endpoint_services = [
    "com.amazonaws.us-east-1.logs",
    "com.amazonaws.us-east-1.s3",
    "com.amazonaws.us-east-1.ec2",
    "com.amazonaws.us-east-1.ssm",
    "com.amazonaws.us-east-1.ssmmessages",
    "com.amazonaws.us-east-1.ec2messages"
  ]
  vpc_endpoint_private_dns_enabled = true
  vpc_endpoint_ip_address_type = var.enable_ipv6 ? "dualstack" : "ipv4"
  
  # ==============================================================================
  # Enterprise VPC Flow Logs Configuration
  # ==============================================================================
  
  enable_flow_logs = true
  flow_logs_traffic_type = "ALL"
  flow_logs_retention_days = 2555 # 7 years for compliance
  
  # ==============================================================================
  # Enterprise Tags and Metadata
  # ==============================================================================
  
  common_tags = {
    Environment = "production"
    Project     = "enterprise-network-security"
    Owner       = "security-team"
    CostCenter  = "security"
    Component   = "network-firewall"
    ManagedBy   = "terraform"
    DataClassification = "confidential"
    Compliance = "SOC2,HIPAA,PCI"
    Backup = "enabled"
    DR = "enabled"
    Security = "high"
    NetworkTier = "enterprise"
    BusinessUnit = "IT"
    Application = "network-security"
    Version = "2.0"
  }
}

# ==============================================================================
# Enterprise Outputs
# ==============================================================================

output "enterprise_transit_gateway_id" {
  description = "Enterprise Transit Gateway ID"
  value       = module.enterprise_network_firewall.transit_gateway_id
}

output "enterprise_network_firewall_id" {
  description = "Enterprise Network Firewall ID"
  value       = module.enterprise_network_firewall.network_firewall_id
}

output "enterprise_firewall_vpc_id" {
  description = "Enterprise Firewall VPC ID"
  value       = module.enterprise_network_firewall.firewall_vpc_id
}

output "enterprise_firewall_logs_bucket" {
  description = "Enterprise S3 bucket for firewall logs"
  value       = module.enterprise_network_firewall.firewall_logs_s3_bucket
}

output "enterprise_cloudwatch_log_group" {
  description = "Enterprise CloudWatch log group for firewall logs"
  value       = module.enterprise_network_firewall.cloudwatch_log_group_name
}

output "enterprise_firewall_policy_arn" {
  description = "Enterprise Network Firewall Policy ARN"
  value       = module.enterprise_network_firewall.firewall_policy_arn
}

output "enterprise_stateless_rule_group_arn" {
  description = "Enterprise Stateless Rule Group ARN"
  value       = module.enterprise_network_firewall.stateless_rule_group_arn
}

output "enterprise_stateful_rule_group_arn" {
  description = "Enterprise Stateful Rule Group ARN"
  value       = module.enterprise_network_firewall.stateful_rule_group_arn
}

output "enterprise_configuration_summary" {
  description = "Summary of enterprise configuration"
  value = {
    high_availability = local.enterprise_config.enable_high_availability
    multi_az_deployment = local.enterprise_config.enable_multi_az_deployment
    advanced_monitoring = local.enterprise_config.enable_advanced_monitoring
    compliance_features = local.enterprise_config.enable_compliance_features
    security_enhancements = local.enterprise_config.enable_security_enhancements
    ipv6_enabled = var.enable_ipv6
    multicast_enabled = var.enable_multicast
    appliance_mode_enabled = var.enable_appliance_mode
    kms_encryption_enabled = var.enable_kms_encryption
    blocked_domains_count = length(module.enterprise_network_firewall.blocked_domains)
  }
} 