# =============================================================================
# Variables for Transit Gateway → Network Firewall → VPC Traffic Inspection
# =============================================================================

variable "name_prefix" {
  description = "Prefix to be used for all resource names"
  type        = string
  default     = "network-firewall"

  validation {
    condition     = can(regex("^[a-z0-9-]+$", var.name_prefix))
    error_message = "Name prefix must contain only lowercase letters, numbers, and hyphens."
  }
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

variable "tgw_description" {
  description = "Description for the Transit Gateway"
  type        = string
  default     = "Transit Gateway for Network Firewall Traffic Inspection"
}

variable "firewall_vpc_cidr" {
  description = "CIDR block for the Network Firewall VPC"
  type        = string
  default     = "10.100.0.0/16"

  validation {
    condition     = can(cidrhost(var.firewall_vpc_cidr, 0))
    error_message = "Must be a valid CIDR block."
  }
}

variable "availability_zones" {
  description = "List of availability zones to deploy resources"
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

variable "blocked_domains" {
  description = "List of domains to block in the Network Firewall"
  type        = list(string)
  default     = ["malware.example.com", "phishing.example.com"]

  validation {
    condition     = length(var.blocked_domains) >= 0
    error_message = "Blocked domains list cannot be negative."
  }
}

variable "log_retention_days" {
  description = "Number of days to retain CloudWatch logs"
  type        = number
  default     = 30

  validation {
    condition     = var.log_retention_days >= 1 && var.log_retention_days <= 3653
    error_message = "Log retention days must be between 1 and 3653."
  }
}

variable "vpc_endpoint_services" {
  description = "List of VPC endpoint services to create"
  type        = list(string)
  default = [
    "com.amazonaws.us-east-1.logs",
    "com.amazonaws.us-east-1.s3"
  ]
}

variable "enable_flow_logs" {
  description = "Enable VPC Flow Logs for the firewall VPC"
  type        = bool
  default     = true
}

variable "enable_network_firewall_logging" {
  description = "Enable logging for Network Firewall"
  type        = bool
  default     = true
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
  description = "Capacity for stateful rule groups"
  type        = number
  default     = 100

  validation {
    condition     = var.stateful_rule_capacity >= 1 && var.stateful_rule_capacity <= 30000
    error_message = "Stateful rule capacity must be between 1 and 30000."
  }
}

variable "stateless_rule_capacity" {
  description = "Capacity for stateless rule groups"
  type        = number
  default     = 100

  validation {
    condition     = var.stateless_rule_capacity >= 1 && var.stateless_rule_capacity <= 30000
    error_message = "Stateless rule capacity must be between 1 and 30000."
  }
}

variable "enable_s3_logging" {
  description = "Enable S3 logging for Network Firewall"
  type        = bool
  default     = true
}

variable "enable_cloudwatch_logging" {
  description = "Enable CloudWatch logging for Network Firewall"
  type        = bool
  default     = true
}

variable "s3_bucket_encryption" {
  description = "Encryption algorithm for S3 bucket"
  type        = string
  default     = "AES256"

  validation {
    condition     = contains(["AES256", "aws:kms"], var.s3_bucket_encryption)
    error_message = "S3 bucket encryption must be either AES256 or aws:kms."
  }
}

variable "transit_gateway_auto_accept_shared_attachments" {
  description = "Whether to automatically accept shared attachments"
  type        = string
  default     = "disable"

  validation {
    condition     = contains(["enable", "disable"], var.transit_gateway_auto_accept_shared_attachments)
    error_message = "Auto accept shared attachments must be either enable or disable."
  }
}

variable "transit_gateway_default_route_table_association" {
  description = "Whether to associate with default route table"
  type        = string
  default     = "enable"

  validation {
    condition     = contains(["enable", "disable"], var.transit_gateway_default_route_table_association)
    error_message = "Default route table association must be either enable or disable."
  }
}

variable "transit_gateway_default_route_table_propagation" {
  description = "Whether to propagate to default route table"
  type        = string
  default     = "enable"

  validation {
    condition     = contains(["enable", "disable"], var.transit_gateway_default_route_table_propagation)
    error_message = "Default route table propagation must be either enable or disable."
  }
}

variable "transit_gateway_dns_support" {
  description = "Whether to enable DNS support"
  type        = string
  default     = "enable"

  validation {
    condition     = contains(["enable", "disable"], var.transit_gateway_dns_support)
    error_message = "DNS support must be either enable or disable."
  }
}

variable "transit_gateway_vpn_ecmp_support" {
  description = "Whether to enable VPN ECMP support"
  type        = string
  default     = "enable"

  validation {
    condition     = contains(["enable", "disable"], var.transit_gateway_vpn_ecmp_support)
    error_message = "VPN ECMP support must be either enable or disable."
  }
}

variable "transit_gateway_multicast_support" {
  description = "Whether to enable multicast support"
  type        = string
  default     = "disable"

  validation {
    condition     = contains(["enable", "disable"], var.transit_gateway_multicast_support)
    error_message = "Multicast support must be either enable or disable."
  }
} 