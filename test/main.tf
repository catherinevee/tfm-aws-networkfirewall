# =============================================================================
# Test Configuration for AWS Network Firewall Module
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

# Test the module with minimal configuration
module "network_firewall_test" {
  source = "../"

  name_prefix = "test-firewall"
  
  availability_zones = ["us-east-1a", "us-east-1b"]
  
  firewall_vpc_cidr = "10.50.0.0/16"
  firewall_public_subnets  = ["10.50.1.0/24", "10.50.2.0/24"]
  firewall_private_subnets = ["10.50.10.0/24", "10.50.11.0/24"]
  
  blocked_domains = [
    "test-malware.example.com",
    "test-phishing.example.com"
  ]
  
  log_retention_days = 7
  
  common_tags = {
    Environment = "test"
    Project     = "module-testing"
    Owner       = "test-team"
    Purpose     = "testing"
  }
}

# Test outputs
output "test_transit_gateway_id" {
  description = "Test Transit Gateway ID"
  value       = module.network_firewall_test.transit_gateway_id
}

output "test_network_firewall_id" {
  description = "Test Network Firewall ID"
  value       = module.network_firewall_test.network_firewall_id
}

output "test_firewall_vpc_id" {
  description = "Test Firewall VPC ID"
  value       = module.network_firewall_test.firewall_vpc_id
}

output "test_complete_info" {
  description = "Complete test information"
  value = {
    transit_gateway = module.network_firewall_test.transit_gateway_info
    network_firewall = module.network_firewall_test.network_firewall_endpoints
    firewall_vpc = module.network_firewall_test.firewall_vpc_info
    logging = module.network_firewall_test.logging_info
  }
} 