# =============================================================================
# Variables for Advanced Enterprise Network Firewall Example
# Enhanced with comprehensive customization options for enterprise deployments
# =============================================================================

# ==============================================================================
# Basic Configuration Variables
# ==============================================================================

variable "vpc_id" {
  description = "VPC ID for data source reference"
  type        = string
  default     = ""
}

# ==============================================================================
# Enterprise Feature Toggle Variables
# ==============================================================================

variable "enable_ipv6" {
  description = "Whether to enable IPv6 support. Default: false"
  type        = bool
  default     = false
}

variable "enable_multicast" {
  description = "Whether to enable multicast support on Transit Gateway. Default: false"
  type        = bool
  default     = false
}

variable "enable_appliance_mode" {
  description = "Whether to enable appliance mode on VPC attachment. Default: false"
  type        = bool
  default     = false
}

variable "enable_kms_encryption" {
  description = "Whether to enable KMS encryption for S3 and CloudWatch. Default: false"
  type        = bool
  default     = false
}

# ==============================================================================
# Security Configuration Variables
# ==============================================================================

variable "additional_blocked_domains" {
  description = "Additional domains to block beyond the default enterprise list"
  type        = list(string)
  default     = []

  validation {
    condition     = length(var.additional_blocked_domains) >= 0
    error_message = "Additional blocked domains list cannot be negative."
  }
}

# ==============================================================================
# KMS Configuration Variables
# ==============================================================================

variable "kms_key_id" {
  description = "KMS key ID for encryption. Required when enable_kms_encryption = true"
  type        = string
  default     = null
}

# ==============================================================================
# Enterprise Configuration Variables
# ==============================================================================

variable "enterprise_name_prefix" {
  description = "Prefix for enterprise resource names"
  type        = string
  default     = "enterprise-firewall"

  validation {
    condition     = can(regex("^[a-z0-9-]+$", var.enterprise_name_prefix))
    error_message = "Enterprise name prefix must contain only lowercase letters, numbers, and hyphens."
  }
}

variable "enterprise_environment" {
  description = "Enterprise environment name"
  type        = string
  default     = "production"

  validation {
    condition     = contains(["development", "staging", "production"], var.enterprise_environment)
    error_message = "Enterprise environment must be one of: development, staging, production."
  }
}

variable "enterprise_project" {
  description = "Enterprise project name"
  type        = string
  default     = "enterprise-network-security"
}

variable "enterprise_owner" {
  description = "Enterprise resource owner"
  type        = string
  default     = "security-team"
}

variable "enterprise_cost_center" {
  description = "Enterprise cost center"
  type        = string
  default     = "security"
}

variable "enterprise_business_unit" {
  description = "Enterprise business unit"
  type        = string
  default     = "IT"
}

variable "enterprise_application" {
  description = "Enterprise application name"
  type        = string
  default     = "network-security"
}

variable "enterprise_version" {
  description = "Enterprise module version"
  type        = string
  default     = "2.0"
}

# ==============================================================================
# Compliance Configuration Variables
# ==============================================================================

variable "compliance_requirements" {
  description = "Compliance requirements for the deployment"
  type        = list(string)
  default     = ["SOC2", "HIPAA", "PCI"]

  validation {
    condition = alltrue([
      for req in var.compliance_requirements : contains(["SOC2", "HIPAA", "PCI", "SOX", "GDPR", "ISO27001"], req)
    ])
    error_message = "Compliance requirements must be valid standards."
  }
}

variable "data_classification" {
  description = "Data classification level"
  type        = string
  default     = "confidential"

  validation {
    condition     = contains(["public", "internal", "confidential", "restricted"], var.data_classification)
    error_message = "Data classification must be one of: public, internal, confidential, restricted."
  }
}

# ==============================================================================
# Network Configuration Variables
# ==============================================================================

variable "enterprise_vpc_cidr" {
  description = "Enterprise VPC CIDR block"
  type        = string
  default     = "10.200.0.0/16"

  validation {
    condition     = can(cidrhost(var.enterprise_vpc_cidr, 0))
    error_message = "Must be a valid CIDR block."
  }
}

variable "enterprise_public_subnets" {
  description = "Enterprise public subnet CIDR blocks"
  type        = list(string)
  default     = ["10.200.1.0/24", "10.200.2.0/24", "10.200.3.0/24"]

  validation {
    condition = alltrue([
      for cidr in var.enterprise_public_subnets : can(cidrhost(cidr, 0))
    ])
    error_message = "All public subnet CIDR blocks must be valid."
  }
}

variable "enterprise_private_subnets" {
  description = "Enterprise private subnet CIDR blocks"
  type        = list(string)
  default     = ["10.200.10.0/24", "10.200.11.0/24", "10.200.12.0/24"]

  validation {
    condition = alltrue([
      for cidr in var.enterprise_private_subnets : can(cidrhost(cidr, 0))
    ])
    error_message = "All private subnet CIDR blocks must be valid."
  }
}

variable "enterprise_availability_zones" {
  description = "Enterprise availability zones"
  type        = list(string)
  default     = ["us-east-1a", "us-east-1b", "us-east-1c"]

  validation {
    condition     = length(var.enterprise_availability_zones) >= 2
    error_message = "At least 2 availability zones are required for high availability."
  }
}

# ==============================================================================
# Transit Gateway Configuration Variables
# ==============================================================================

variable "enterprise_transit_gateway_asn" {
  description = "Enterprise Transit Gateway ASN (Private range: 64512-65534)"
  type        = number
  default     = 64513

  validation {
    condition     = var.enterprise_transit_gateway_asn >= 64512 && var.enterprise_transit_gateway_asn <= 65534
    error_message = "ASN must be in the private range 64512-65534."
  }
}

# ==============================================================================
# Firewall Configuration Variables
# ==============================================================================

variable "enterprise_firewall_protection" {
  description = "Enterprise firewall protection settings"
  type = object({
    delete_protection = bool
    policy_change_protection = bool
    subnet_change_protection = bool
  })
  default = {
    delete_protection = true
    policy_change_protection = true
    subnet_change_protection = true
  }
}

variable "enterprise_rule_capacities" {
  description = "Enterprise rule group capacities"
  type = object({
    stateless = number
    stateful = number
  })
  default = {
    stateless = 1000
    stateful = 1000
  }
}

# ==============================================================================
# Logging Configuration Variables
# ==============================================================================

variable "enterprise_log_retention_days" {
  description = "Enterprise log retention period in days"
  type        = number
  default     = 2555 # 7 years for compliance

  validation {
    condition     = var.enterprise_log_retention_days >= 1 && var.enterprise_log_retention_days <= 3653
    error_message = "Log retention days must be between 1 and 3653."
  }
}

variable "enterprise_s3_lifecycle" {
  description = "Enterprise S3 lifecycle configuration"
  type = object({
    transition_to_ia_days = number
    transition_to_glacier_days = number
    expiration_days = number
    abort_incomplete_multipart_upload_days = number
  })
  default = {
    transition_to_ia_days = 30
    transition_to_glacier_days = 90
    expiration_days = 2555 # 7 years
    abort_incomplete_multipart_upload_days = 7
  }


}

# ==============================================================================
# Security Group Configuration Variables
# ==============================================================================

variable "enterprise_security_group_ingress_rules" {
  description = "Enterprise security group ingress rules"
  type = list(object({
    from_port   = number
    to_port     = number
    protocol    = string
    cidr_blocks = list(string)
    description = string
  }))
  default = [
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


}

# ==============================================================================
# VPC Endpoints Configuration Variables
# ==============================================================================

variable "enterprise_vpc_endpoint_services" {
  description = "Enterprise VPC endpoint services"
  type        = list(string)
  default = [
    "com.amazonaws.us-east-1.logs",
    "com.amazonaws.us-east-1.s3",
    "com.amazonaws.us-east-1.ec2",
    "com.amazonaws.us-east-1.ssm",
    "com.amazonaws.us-east-1.ssmmessages",
    "com.amazonaws.us-east-1.ec2messages"
  ]
}

# ==============================================================================
# Tags Configuration Variables
# ==============================================================================

variable "enterprise_common_tags" {
  description = "Enterprise common tags"
  type        = map(string)
  default = {
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