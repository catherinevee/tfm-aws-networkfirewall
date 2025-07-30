# =============================================================================
# Basic Example: Network Firewall with Transit Gateway
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

module "network_firewall" {
  source = "../../"

  name_prefix = "basic-firewall"
  
  availability_zones = ["us-east-1a", "us-east-1b"]
  
  firewall_vpc_cidr = "10.100.0.0/16"
  firewall_public_subnets  = ["10.100.1.0/24", "10.100.2.0/24"]
  firewall_private_subnets = ["10.100.10.0/24", "10.100.11.0/24"]
  
  blocked_domains = [
    "malware.example.com",
    "phishing.example.com",
    "suspicious-site.com"
  ]
  
  log_retention_days = 30
  
  common_tags = {
    Environment = "development"
    Project     = "network-security"
    Owner       = "security-team"
    CostCenter  = "security"
  }
}

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