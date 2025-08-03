# =============================================================================
# Variables for Transit Gateway → Network Firewall → VPC Traffic Inspection
# =============================================================================

variable "name_prefix" {
  type        = string
  description = "Prefix for resource names"
  validation {
    condition     = length(var.name_prefix) <= 32 && can(regex("^[a-z0-9-]+$", var.name_prefix))
    error_message = "Name prefix must be 32 characters or less and contain only lowercase letters, numbers, and hyphens."
  }
}

variable "transit_gateway_asn" {
  type        = number
  description = "ASN for Transit Gateway. Must be in private ASN range."
  default     = 64512
  validation {
    condition     = var.transit_gateway_asn >= 64512 && var.transit_gateway_asn <= 65534
    error_message = "ASN must be in the private range (64512-65534)."
  }
}

variable "firewall_vpc_cidr" {
  type        = string
  description = "CIDR block for the firewall VPC"
  default     = "10.100.0.0/16"
  validation {
    condition     = can(cidrhost(var.firewall_vpc_cidr, 0))
    error_message = "Must be a valid CIDR block."
  }
}

variable "firewall_config" {
  type = object({
    policy_name = string
    description = optional(string)
    stateful_rules = optional(list(object({
      name     = string
      priority = number
      actions  = list(string)
    })))
    stateless_rules = optional(list(object({
      name     = string
      priority = number
      actions  = list(string)
    })))
  })
  description = "Comprehensive firewall configuration object"
  default = null
}

variable "monitoring_config" {
  type = object({
    enable_cloudwatch = optional(bool, true)
    retention_days   = optional(number, 30)
    alert_threshold  = optional(number)
  })
  description = "Monitoring configuration with optional settings"
  default = {}
}

variable "common_tags" {
  description = "Common tags to be applied to all resources"
  type        = map(string)
  default = {
    Environment = "production"
    Project     = "network-firewall"
    ManagedBy   = "terraform"
  }
}

# ==============================================================================
# Transit Gateway Configuration Variables
# ==============================================================================

variable "tgw_description" {
  description = "Description for the Transit Gateway"
  type        = string
  default     = "Transit Gateway for Network Firewall Traffic Inspection"
}

variable "transit_gateway_asn" {
  description = "Private ASN for the Transit Gateway. Default: 64512 (Private ASN range 64512-65534)"
  type        = number
  default     = 64512
  validation {
    condition     = var.transit_gateway_asn >= 64512 && var.transit_gateway_asn <= 65534
    error_message = "ASN must be in the private range 64512-65534."
  }
}

variable "transit_gateway_auto_accept_shared_attachments" {
  description = "Whether to automatically accept shared attachments. Options: enable, disable"
  type        = string
  default     = "disable"

  validation {
    condition     = contains(["enable", "disable"], var.transit_gateway_auto_accept_shared_attachments)
    error_message = "Auto accept shared attachments must be either enable or disable."
  }
}

variable "transit_gateway_default_route_table_association" {
  description = "Whether to associate with default route table. Options: enable, disable"
  type        = string
  default     = "enable"

  validation {
    condition     = contains(["enable", "disable"], var.transit_gateway_default_route_table_association)
    error_message = "Default route table association must be either enable or disable."
  }
}

variable "transit_gateway_default_route_table_propagation" {
  description = "Whether to propagate to default route table. Options: enable, disable"
  type        = string
  default     = "enable"

  validation {
    condition     = contains(["enable", "disable"], var.transit_gateway_default_route_table_propagation)
    error_message = "Default route table propagation must be either enable or disable."
  }
}

variable "transit_gateway_dns_support" {
  description = "Whether to enable DNS support. Options: enable, disable"
  type        = string
  default     = "enable"

  validation {
    condition     = contains(["enable", "disable"], var.transit_gateway_dns_support)
    error_message = "DNS support must be either enable or disable."
  }
}

variable "transit_gateway_vpn_ecmp_support" {
  description = "Whether to enable VPN ECMP support. Options: enable, disable"
  type        = string
  default     = "enable"

  validation {
    condition     = contains(["enable", "disable"], var.transit_gateway_vpn_ecmp_support)
    error_message = "VPN ECMP support must be either enable or disable."
  }
}

variable "transit_gateway_multicast_support" {
  description = "Whether to enable multicast support. Options: enable, disable"
  type        = string
  default     = "disable"

  validation {
    condition     = contains(["enable", "disable"], var.transit_gateway_multicast_support)
    error_message = "Multicast support must be either enable or disable."
  }
}

variable "transit_gateway_appliance_mode_support" {
  description = "Whether to enable appliance mode support on VPC attachment. Options: enable, disable"
  type        = string
  default     = "disable"

  validation {
    condition     = contains(["enable", "disable"], var.transit_gateway_appliance_mode_support)
    error_message = "Appliance mode support must be either enable or disable."
  }
}

variable "transit_gateway_ipv6_support" {
  description = "Whether to enable IPv6 support on VPC attachment. Options: enable, disable"
  type        = string
  default     = "disable"

  validation {
    condition     = contains(["enable", "disable"], var.transit_gateway_ipv6_support)
    error_message = "IPv6 support must be either enable or disable."
  }
}

# ==============================================================================
# VPC Configuration Variables
# ==============================================================================

variable "firewall_vpc_cidr" {
  description = "CIDR block for the Network Firewall VPC. Default: 10.100.0.0/16"
  type        = string
  default     = "10.100.0.0/16"

  validation {
    condition     = can(cidrhost(var.firewall_vpc_cidr, 0))
    error_message = "Must be a valid CIDR block."
  }
}

variable "enable_dns_hostnames" {
  description = "Whether to enable DNS hostnames in the VPC. Default: true"
  type        = bool
  default     = true
}

variable "enable_dns_support" {
  description = "Whether to enable DNS support in the VPC. Default: true"
  type        = bool
  default     = true
}

variable "vpc_instance_tenancy" {
  description = "Tenancy of instances launched into the VPC. Options: default, dedicated"
  type        = string
  default     = "default"

  validation {
    condition     = contains(["default", "dedicated"], var.vpc_instance_tenancy)
    error_message = "Instance tenancy must be either default or dedicated."
  }
}

variable "vpc_ipv4_ipam_pool_id" {
  description = "The ID of an IPv4 IPAM pool for the VPC. Optional: Custom IPAM pool"
  type        = string
  default     = null
}

variable "vpc_ipv4_netmask_length" {
  description = "The netmask length of the IPv4 CIDR for the VPC. Optional: Custom netmask"
  type        = number
  default     = null

  validation {
    condition     = var.vpc_ipv4_netmask_length == null || (var.vpc_ipv4_netmask_length >= 16 && var.vpc_ipv4_netmask_length <= 28)
    error_message = "IPv4 netmask length must be between 16 and 28."
  }
}

# ==============================================================================
# Subnet Configuration Variables
# ==============================================================================

variable "availability_zones" {
  description = "List of availability zones to deploy resources. Minimum 2 AZs required for HA"
  type        = list(string)
  default     = ["us-east-1a", "us-east-1b"]

  validation {
    condition     = length(var.availability_zones) >= 2
    error_message = "At least 2 availability zones are required for high availability."
  }
}

variable "firewall_public_subnets" {
  description = "List of CIDR blocks for public subnets in the firewall VPC"
  type        = list(string)
  default     = ["10.100.1.0/24", "10.100.2.0/24"]

  validation {
    condition = alltrue([
      for cidr in var.firewall_public_subnets : can(cidrhost(cidr, 0))
    ])
    error_message = "All subnet CIDR blocks must be valid."
  }
}

variable "firewall_private_subnets" {
  description = "List of CIDR blocks for private subnets in the firewall VPC"
  type        = list(string)
  default     = ["10.100.10.0/24", "10.100.11.0/24"]

  validation {
    condition = alltrue([
      for cidr in var.firewall_private_subnets : can(cidrhost(cidr, 0))
    ])
    error_message = "All subnet CIDR blocks must be valid."
  }
}

variable "firewall_public_subnet_map_public_ip" {
  description = "Whether to map public IP on launch for public subnets. Default: false"
  type        = bool
  default     = false
}

variable "enable_ipv6" {
  description = "Whether to enable IPv6 support. Default: false"
  type        = bool
  default     = false
}

variable "firewall_public_subnet_ipv6_cidrs" {
  description = "List of IPv6 CIDR blocks for public subnets. Required when enable_ipv6 = true"
  type        = list(string)
  default     = []

  validation {
    condition = alltrue([
      for cidr in var.firewall_public_subnet_ipv6_cidrs : can(cidrhost(cidr, 0))
    ])
    error_message = "All IPv6 subnet CIDR blocks must be valid."
  }
}

variable "firewall_private_subnet_ipv6_cidrs" {
  description = "List of IPv6 CIDR blocks for private subnets. Required when enable_ipv6 = true"
  type        = list(string)
  default     = []

  validation {
    condition = alltrue([
      for cidr in var.firewall_private_subnet_ipv6_cidrs : can(cidrhost(cidr, 0))
    ])
    error_message = "All IPv6 subnet CIDR blocks must be valid."
  }
}

# ==============================================================================
# Network Firewall Configuration Variables
# ==============================================================================

variable "firewall_delete_protection" {
  description = "Whether to enable delete protection for the firewall. Default: false"
  type        = bool
  default     = false
}

variable "firewall_policy_change_protection" {
  description = "Whether to enable policy change protection for the firewall. Default: false"
  type        = bool
  default     = false
}

variable "firewall_subnet_change_protection" {
  description = "Whether to enable subnet change protection for the firewall. Default: false"
  type        = bool
  default     = false
}

variable "enable_stateless_rules" {
  description = "Whether to enable stateless rule group. Default: true"
  type        = bool
  default     = true
}

variable "enable_stateful_rules" {
  description = "Whether to enable stateful rule group. Default: true"
  type        = bool
  default     = true
}

variable "enable_stateful_engine_options" {
  description = "Whether to enable stateful engine options. Default: false"
  type        = bool
  default     = false
}

variable "stateless_rule_priority" {
  description = "Priority for stateless rules. Default: 1"
  type        = number
  default     = 1

  validation {
    condition     = var.stateless_rule_priority >= 1 && var.stateless_rule_priority <= 65535
    error_message = "Stateless rule priority must be between 1 and 65535."
  }
}

variable "stateful_rule_priority" {
  description = "Priority for stateful rules. Default: 2"
  type        = number
  default     = 2

  validation {
    condition     = var.stateful_rule_priority >= 1 && var.stateful_rule_priority <= 65535
    error_message = "Stateful rule priority must be between 1 and 65535."
  }
}

variable "stateful_rule_order" {
  description = "Rule order for stateful engine. Options: DEFAULT_ACTION_ORDER, STRICT_ORDER"
  type        = string
  default     = "DEFAULT_ACTION_ORDER"

  validation {
    condition     = contains(["DEFAULT_ACTION_ORDER", "STRICT_ORDER"], var.stateful_rule_order)
    error_message = "Stateful rule order must be either DEFAULT_ACTION_ORDER or STRICT_ORDER."
  }
}

variable "stateless_rule_actions" {
  description = "Actions for stateless rules. Default: forward to stateful engine"
  type        = list(string)
  default     = ["aws:forward_to_sfe"]

  validation {
    condition = alltrue([
      for action in var.stateless_rule_actions : contains(["aws:forward_to_sfe", "aws:drop", "aws:pass"], action)
    ])
    error_message = "Stateless rule actions must be one of: aws:forward_to_sfe, aws:drop, aws:pass."
  }
}

variable "stateless_rule_destination_cidr" {
  description = "Destination CIDR for stateless rules. Default: 0.0.0.0/0 (all destinations)"
  type        = string
  default     = "0.0.0.0/0"

  validation {
    condition     = can(cidrhost(var.stateless_rule_destination_cidr, 0))
    error_message = "Must be a valid CIDR block."
  }
}

variable "stateless_rule_source_cidr" {
  description = "Source CIDR for stateless rules. Default: 0.0.0.0/0 (all sources)"
  type        = string
  default     = "0.0.0.0/0"

  validation {
    condition     = can(cidrhost(var.stateless_rule_source_cidr, 0))
    error_message = "Must be a valid CIDR block."
  }
}

variable "stateless_rule_protocols" {
  description = "Protocols for stateless rules. Default: [1, 6, 17] (ICMP, TCP, UDP)"
  type        = list(number)
  default     = [1, 6, 17]

  validation {
    condition = alltrue([
      for protocol in var.stateless_rule_protocols : protocol >= 1 && protocol <= 255
    ])
    error_message = "Protocol numbers must be between 1 and 255."
  }
}

variable "stateful_rules_generated_type" {
  description = "Generated rules type for stateful rules. Options: DENYLIST, ALLOWLIST"
  type        = string
  default     = "DENYLIST"

  validation {
    condition     = contains(["DENYLIST", "ALLOWLIST"], var.stateful_rules_generated_type)
    error_message = "Generated rules type must be either DENYLIST or ALLOWLIST."
  }
}

variable "stateful_rules_target_types" {
  description = "Target types for stateful rules. Default: HTTP_HOST and TLS_SNI"
  type        = list(string)
  default     = ["HTTP_HOST", "TLS_SNI"]

  validation {
    condition = alltrue([
      for target_type in var.stateful_rules_target_types : contains(["HTTP_HOST", "TLS_SNI", "HTTP_URI", "TLS_SNI_AND_HTTP_HOST"], target_type)
    ])
    error_message = "Target types must be valid Network Firewall target types."
  }
}

variable "blocked_domains" {
  description = "List of domains to block in the Network Firewall"
  type        = list(string)
  default     = ["malware.example.com", "phishing.example.com"]

  validation {
    condition     = length(var.blocked_domains) >= 0
    error_message = "Blocked domains list cannot be negative."
  }
}

variable "firewall_policy_stateless_default_actions" {
  description = "Default actions for stateless traffic in the firewall policy"
  type        = list(string)
  default     = ["aws:forward_to_sfe"]

  validation {
    condition = alltrue([
      for action in var.firewall_policy_stateless_default_actions : contains(["aws:forward_to_sfe", "aws:drop", "aws:pass"], action)
    ])
    error_message = "Stateless default actions must be one of: aws:forward_to_sfe, aws:drop, aws:pass."
  }
}

variable "firewall_policy_stateless_fragment_default_actions" {
  description = "Default actions for stateless fragment traffic in the firewall policy"
  type        = list(string)
  default     = ["aws:forward_to_sfe"]

  validation {
    condition = alltrue([
      for action in var.firewall_policy_stateless_fragment_default_actions : contains(["aws:forward_to_sfe", "aws:drop", "aws:pass"], action)
    ])
    error_message = "Stateless fragment default actions must be one of: aws:forward_to_sfe, aws:drop, aws:pass."
  }
}

variable "stateful_rule_capacity" {
  description = "Capacity for stateful rule groups. Range: 1-30000"
  type        = number
  default     = 100

  validation {
    condition     = var.stateful_rule_capacity >= 1 && var.stateful_rule_capacity <= 30000
    error_message = "Stateful rule capacity must be between 1 and 30000."
  }
}

variable "stateless_rule_capacity" {
  description = "Capacity for stateless rule groups. Range: 1-30000"
  type        = number
  default     = 100

  validation {
    condition     = var.stateless_rule_capacity >= 1 && var.stateless_rule_capacity <= 30000
    error_message = "Stateless rule capacity must be between 1 and 30000."
  }
}

# ==============================================================================
# Logging Configuration Variables
# ==============================================================================

variable "enable_network_firewall_logging" {
  description = "Enable logging for Network Firewall. Default: true"
  type        = bool
  default     = true
}

variable "enable_s3_logging" {
  description = "Enable S3 logging for Network Firewall. Default: true"
  type        = bool
  default     = true
}

variable "enable_cloudwatch_logging" {
  description = "Enable CloudWatch logging for Network Firewall. Default: true"
  type        = bool
  default     = true
}

variable "s3_log_prefix" {
  description = "S3 prefix for firewall logs. Default: firewall-logs/"
  type        = string
  default     = "firewall-logs/"
}

variable "s3_alert_log_prefix" {
  description = "S3 prefix for alert logs. Default: alert-logs/"
  type        = string
  default     = "alert-logs/"
}

variable "log_retention_days" {
  description = "Number of days to retain CloudWatch logs. Range: 1-3653"
  type        = number
  default     = 30

  validation {
    condition     = var.log_retention_days >= 1 && var.log_retention_days <= 3653
    error_message = "Log retention days must be between 1 and 3653."
  }
}

# ==============================================================================
# S3 Configuration Variables
# ==============================================================================

variable "s3_bucket_encryption" {
  description = "Encryption algorithm for S3 bucket. Options: AES256, aws:kms"
  type        = string
  default     = "AES256"

  validation {
    condition     = contains(["AES256", "aws:kms"], var.s3_bucket_encryption)
    error_message = "S3 bucket encryption must be either AES256 or aws:kms."
  }
}

variable "s3_bucket_kms_key_id" {
  description = "KMS key ID for S3 bucket encryption. Required when s3_bucket_encryption = aws:kms"
  type        = string
  default     = null
}

variable "s3_bucket_key_enabled" {
  description = "Whether to enable bucket key for S3. Default: true"
  type        = bool
  default     = true
}

variable "s3_bucket_force_destroy" {
  description = "Whether to force destroy S3 bucket. Default: false"
  type        = bool
  default     = false
}

variable "s3_bucket_versioning_status" {
  description = "Versioning status for S3 bucket. Options: Enabled, Suspended"
  type        = string
  default     = "Enabled"

  validation {
    condition     = contains(["Enabled", "Suspended"], var.s3_bucket_versioning_status)
    error_message = "S3 bucket versioning status must be either Enabled or Suspended."
  }
}

variable "s3_block_public_acls" {
  description = "Whether to block public ACLs on S3 bucket. Default: true"
  type        = bool
  default     = true
}

variable "s3_block_public_policy" {
  description = "Whether to block public policy on S3 bucket. Default: true"
  type        = bool
  default     = true
}

variable "s3_ignore_public_acls" {
  description = "Whether to ignore public ACLs on S3 bucket. Default: true"
  type        = bool
  default     = true
}

variable "s3_restrict_public_buckets" {
  description = "Whether to restrict public buckets. Default: true"
  type        = bool
  default     = true
}

variable "enable_s3_lifecycle" {
  description = "Whether to enable S3 lifecycle configuration. Default: false"
  type        = bool
  default     = false
}

variable "s3_transition_to_ia_days" {
  description = "Days to transition objects to IA storage. 0 to disable. Default: 0"
  type        = number
  default     = 0

  validation {
    condition     = var.s3_transition_to_ia_days >= 0
    error_message = "Transition to IA days must be 0 or greater."
  }
}

variable "s3_transition_to_glacier_days" {
  description = "Days to transition objects to Glacier storage. 0 to disable. Default: 0"
  type        = number
  default     = 0

  validation {
    condition     = var.s3_transition_to_glacier_days >= 0
    error_message = "Transition to Glacier days must be 0 or greater."
  }
}

variable "s3_expiration_days" {
  description = "Days to expire objects. Default: 2555 (7 years)"
  type        = number
  default     = 2555

  validation {
    condition     = var.s3_expiration_days >= 1
    error_message = "S3 expiration days must be 1 or greater."
  }
}

variable "s3_abort_incomplete_multipart_upload_days" {
  description = "Days to abort incomplete multipart uploads. Default: 7"
  type        = number
  default     = 7

  validation {
    condition     = var.s3_abort_incomplete_multipart_upload_days >= 1
    error_message = "Abort incomplete multipart upload days must be 1 or greater."
  }
}

variable "bucket_suffix_length" {
  description = "Length of random bucket suffix. Default: 8"
  type        = number
  default     = 8

  validation {
    condition     = var.bucket_suffix_length >= 1 && var.bucket_suffix_length <= 32
    error_message = "Bucket suffix length must be between 1 and 32."
  }
}

variable "bucket_suffix_special" {
  description = "Whether to include special characters in bucket suffix. Default: false"
  type        = bool
  default     = false
}

variable "bucket_suffix_upper" {
  description = "Whether to include uppercase letters in bucket suffix. Default: false"
  type        = bool
  default     = false
}

variable "bucket_suffix_lower" {
  description = "Whether to include lowercase letters in bucket suffix. Default: true"
  type        = bool
  default     = true
}

variable "bucket_suffix_numeric" {
  description = "Whether to include numbers in bucket suffix. Default: true"
  type        = bool
  default     = true
}

# ==============================================================================
# CloudWatch Configuration Variables
# ==============================================================================

variable "cloudwatch_kms_key_id" {
  description = "KMS key ID for CloudWatch log group encryption. Optional"
  type        = string
  default     = null
}

variable "enable_metric_filters" {
  description = "Whether to enable CloudWatch metric filters. Default: false"
  type        = bool
  default     = false
}

variable "cloudwatch_alert_pattern" {
  description = "Pattern for CloudWatch alert metric filter. Default: basic alert pattern"
  type        = string
  default     = "[timestamp, action=BLOCK, ...]"
}

# ==============================================================================
# IAM Configuration Variables
# ==============================================================================

variable "iam_role_path" {
  description = "Path for IAM roles. Default: /"
  type        = string
  default     = "/"
}

variable "enable_advanced_permissions" {
  description = "Whether to enable advanced IAM permissions. Default: false"
  type        = bool
  default     = false
}

# ==============================================================================
# Security Groups Configuration Variables
# ==============================================================================

variable "firewall_security_group_egress_cidrs" {
  description = "Egress CIDR blocks for firewall security group. Default: all traffic"
  type        = list(string)
  default     = ["0.0.0.0/0"]

  validation {
    condition = alltrue([
      for cidr in var.firewall_security_group_egress_cidrs : can(cidrhost(cidr, 0))
    ])
    error_message = "All egress CIDR blocks must be valid."
  }
}

variable "firewall_security_group_ingress_rules" {
  description = "Ingress rules for firewall security group"
  type = list(object({
    from_port   = number
    to_port     = number
    protocol    = string
    cidr_blocks = list(string)
    description = string
  }))
  default = []

  validation {
    condition = alltrue([
      for rule in var.firewall_security_group_ingress_rules : 
      alltrue([
        for cidr in rule.cidr_blocks : can(cidrhost(cidr, 0))
      ])
    ])
    error_message = "All ingress rule CIDR blocks must be valid."
  }
}

# ==============================================================================
# VPC Endpoints Configuration Variables
# ==============================================================================

variable "vpc_endpoint_services" {
  description = "List of VPC endpoint services to create"
  type        = list(string)
  default = [
    "com.amazonaws.us-east-1.logs",
    "com.amazonaws.us-east-1.s3"
  ]
}

variable "vpc_endpoint_private_dns_enabled" {
  description = "Whether to enable private DNS for VPC endpoints. Default: true"
  type        = bool
  default     = true
}

variable "vpc_endpoint_ip_address_type" {
  description = "IP address type for VPC endpoints. Options: ipv4, dualstack"
  type        = string
  default     = "ipv4"

  validation {
    condition     = contains(["ipv4", "dualstack"], var.vpc_endpoint_ip_address_type)
    error_message = "VPC endpoint IP address type must be either ipv4 or dualstack."
  }
}

# ==============================================================================
# VPC Flow Logs Configuration Variables
# ==============================================================================

variable "enable_flow_logs" {
  description = "Enable VPC Flow Logs for the firewall VPC. Default: true"
  type        = bool
  default     = true
}

variable "flow_logs_traffic_type" {
  description = "Traffic type for VPC Flow Logs. Options: ACCEPT, REJECT, ALL"
  type        = string
  default     = "ALL"

  validation {
    condition     = contains(["ACCEPT", "REJECT", "ALL"], var.flow_logs_traffic_type)
    error_message = "Flow logs traffic type must be either ACCEPT, REJECT, or ALL."
  }
}

variable "flow_logs_retention_days" {
  description = "Number of days to retain VPC Flow Logs. Range: 1-3653"
  type        = number
  default     = 30

  validation {
    condition     = var.flow_logs_retention_days >= 1 && var.flow_logs_retention_days <= 3653
    error_message = "Flow logs retention days must be between 1 and 3653."
  }
}