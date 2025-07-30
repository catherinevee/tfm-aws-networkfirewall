# =============================================================================
# Advanced Example: Enterprise Network Firewall with Transit Gateway
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

  name_prefix = "enterprise-firewall"
  
  availability_zones = ["us-east-1a", "us-east-1b", "us-east-1c"]
  
  firewall_vpc_cidr = "10.200.0.0/16"
  firewall_public_subnets  = ["10.200.1.0/24", "10.200.2.0/24", "10.200.3.0/24"]
  firewall_private_subnets = ["10.200.10.0/24", "10.200.11.0/24", "10.200.12.0/24"]
  
  blocked_domains = [
    "malware.example.com",
    "phishing.example.com",
    "suspicious-site.com",
    "tor-exit-node.com",
    "botnet-command.com",
    "crypto-mining-pool.com",
    "data-exfiltration.com",
    "command-control.com"
  ]
  
  log_retention_days = 90
  
  vpc_endpoint_services = [
    "com.amazonaws.us-east-1.logs",
    "com.amazonaws.us-east-1.s3",
    "com.amazonaws.us-east-1.ec2",
    "com.amazonaws.us-east-1.ec2messages",
    "com.amazonaws.us-east-1.ssm",
    "com.amazonaws.us-east-1.ssmmessages",
    "com.amazonaws.us-east-1.secretsmanager",
    "com.amazonaws.us-east-1.kms"
  ]
  
  stateful_rule_capacity = 1000
  stateless_rule_capacity = 1000
  
  enable_flow_logs = true
  enable_network_firewall_logging = true
  enable_s3_logging = true
  enable_cloudwatch_logging = true
  
  s3_bucket_encryption = "AES256"
  
  transit_gateway_auto_accept_shared_attachments = "disable"
  transit_gateway_default_route_table_association = "enable"
  transit_gateway_default_route_table_propagation = "enable"
  transit_gateway_dns_support = "enable"
  transit_gateway_vpn_ecmp_support = "enable"
  transit_gateway_multicast_support = "disable"
  
  common_tags = {
    Environment = "production"
    Project     = "enterprise-security"
    Owner       = "security-team"
    CostCenter  = "security-ops"
    Compliance  = "sox-pci"
    DataClassification = "confidential"
    BackupRequired = "true"
    MonitoringLevel = "high"
  }
}

# Additional resources for enterprise setup

# CloudWatch Dashboard for monitoring
resource "aws_cloudwatch_dashboard" "firewall_monitoring" {
  dashboard_name = "${var.name_prefix}-firewall-dashboard"

  dashboard_body = jsonencode({
    widgets = [
      {
        type   = "metric"
        x      = 0
        y      = 0
        width  = 12
        height = 6

        properties = {
          metrics = [
            ["AWS/NetworkFirewall", "BytesIn", "FirewallName", module.network_firewall.network_firewall_name],
            [".", "BytesOut", ".", "."],
            [".", "PacketsIn", ".", "."],
            [".", "PacketsOut", ".", "."]
          ]
          period = 300
          stat   = "Sum"
          region = "us-east-1"
          title  = "Network Firewall Traffic"
        }
      },
      {
        type   = "metric"
        x      = 12
        y      = 0
        width  = 12
        height = 6

        properties = {
          metrics = [
            ["AWS/NetworkFirewall", "DropCount", "FirewallName", module.network_firewall.network_firewall_name],
            [".", "AlertCount", ".", "."]
          ]
          period = 300
          stat   = "Sum"
          region = "us-east-1"
          title  = "Firewall Alerts and Drops"
        }
      }
    ]
  })
}

# CloudWatch Alarms
resource "aws_cloudwatch_metric_alarm" "firewall_drops" {
  alarm_name          = "${var.name_prefix}-firewall-drops"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "DropCount"
  namespace           = "AWS/NetworkFirewall"
  period              = "300"
  statistic           = "Sum"
  threshold           = "100"
  alarm_description   = "This metric monitors firewall drop count"
  alarm_actions       = [aws_sns_topic.firewall_alerts.arn]

  dimensions = {
    FirewallName = module.network_firewall.network_firewall_name
  }
}

resource "aws_cloudwatch_metric_alarm" "firewall_alerts" {
  alarm_name          = "${var.name_prefix}-firewall-alerts"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "AlertCount"
  namespace           = "AWS/NetworkFirewall"
  period              = "300"
  statistic           = "Sum"
  threshold           = "50"
  alarm_description   = "This metric monitors firewall alert count"
  alarm_actions       = [aws_sns_topic.firewall_alerts.arn]

  dimensions = {
    FirewallName = module.network_firewall.network_firewall_name
  }
}

# SNS Topic for alerts
resource "aws_sns_topic" "firewall_alerts" {
  name = "${var.name_prefix}-firewall-alerts"
}

resource "aws_sns_topic_subscription" "firewall_alerts_email" {
  topic_arn = aws_sns_topic.firewall_alerts.arn
  protocol  = "email"
  endpoint  = "security-team@example.com"
}

# Variables for the advanced example
variable "name_prefix" {
  description = "Prefix for resource names"
  type        = string
  default     = "enterprise-firewall"
}

# Outputs
output "transit_gateway_info" {
  description = "Complete Transit Gateway information"
  value       = module.network_firewall.transit_gateway_info
}

output "network_firewall_endpoints" {
  description = "Network Firewall endpoint information"
  value       = module.network_firewall.network_firewall_endpoints
}

output "firewall_vpc_info" {
  description = "Complete Firewall VPC information"
  value       = module.network_firewall.firewall_vpc_info
}

output "logging_info" {
  description = "Logging configuration information"
  value       = module.network_firewall.logging_info
}

output "cloudwatch_dashboard_url" {
  description = "URL for the CloudWatch dashboard"
  value       = "https://console.aws.amazon.com/cloudwatch/home?region=us-east-1#dashboards:name=${aws_cloudwatch_dashboard.firewall_monitoring.dashboard_name}"
}

output "sns_topic_arn" {
  description = "ARN of the SNS topic for firewall alerts"
  value       = aws_sns_topic.firewall_alerts.arn
} 