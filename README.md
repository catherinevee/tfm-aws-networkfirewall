# AWS Network Firewall with Transit Gateway

A comprehensive Terraform module for deploying AWS Network Firewall with Transit Gateway for enterprise-grade traffic inspection and security.

## 🚀 Features

### Core Connectivity
- **Transit Gateway**: Centralized networking hub with full customization options
- **Network Firewall**: AWS managed firewall service with advanced rule configuration
- **VPC Architecture**: Dedicated firewall VPC with public and private subnets
- **Multi-AZ Deployment**: High availability across multiple availability zones

### Advanced Configuration
- **IPv6 Support**: Optional IPv6 configuration for modern networking
- **Appliance Mode**: Enhanced traffic routing capabilities
- **Multicast Support**: Optional multicast traffic handling
- **Custom ASN**: Configurable Autonomous System Numbers
- **Advanced Routing**: Flexible route table associations and propagations

### Security & Compliance
- **Domain Filtering**: Comprehensive domain blocking with allowlist/denylist support
- **Protocol Filtering**: Configurable protocol-based traffic inspection
- **Stateful/Stateless Rules**: Advanced rule group configuration
- **Security Groups**: Restrictive network access controls
- **VPC Endpoints**: Private connectivity to AWS services

### Monitoring & Logging
- **S3 Logging**: Comprehensive log storage with lifecycle management
- **CloudWatch Integration**: Real-time monitoring and alerting
- **VPC Flow Logs**: Network traffic monitoring
- **Metric Filters**: Custom log analysis and alerting
- **Extended Retention**: Compliance-ready log retention policies

## 📋 Prerequisites

- Terraform >= 1.0
- AWS Provider >= 5.0
- AWS Account with appropriate permissions
- At least 2 availability zones in your target region

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        AWS Network Firewall                     │
│                                                                 │
│  ┌─────────────────┐    ┌─────────────────┐    ┌─────────────┐ │
│  │   Transit       │    │   Network       │    │   VPC       │ │
│  │   Gateway       │◄──►│   Firewall      │◄──►│   Endpoints │ │
│  │                 │    │                 │    │             │ │
│  │ • Route Tables  │    │ • Stateful      │    │ • S3        │ │
│  │ • Attachments   │    │   Rules         │    │ • CloudWatch│ │
│  │ • Multicast     │    │ • Stateless     │    │ • EC2       │ │
│  │ • VPN Support   │    │   Rules         │    │ • SSM       │ │
│  └─────────────────┘    │ • Domain Filter │    └─────────────┘ │
│                         │ • Logging       │                   │
│                         └─────────────────┘                   │
│                                                                 │
│  ┌─────────────────┐    ┌─────────────────┐    ┌─────────────┐ │
│  │   Public        │    │   Private       │    │   Security  │ │
│  │   Subnets       │    │   Subnets       │    │   Groups    │ │
│  │                 │    │                 │    │             │ │
│  │ • Internet      │    │ • VPC           │    │ • Ingress   │ │
│  │   Gateway       │    │   Endpoints     │    │ • Egress    │ │
│  │ • Firewall      │    │ • Flow Logs     │    │ • Protocols │ │
│  │   Endpoints     │    │ • Monitoring    │    │ • CIDR      │ │
│  └─────────────────┘    └─────────────────┘    └─────────────┘ │
└─────────────────────────────────────────────────────────────────┘
```

## 📖 Usage

## Resource Map

| Resource Type | Purpose | Configuration Options |
|--------------|---------|----------------------|
| `aws_ec2_transit_gateway` | Central networking hub | ASN, routing options, multicast support |
| `aws_vpc` | Dedicated firewall VPC | CIDR, DNS settings, IPv6 support |
| `aws_network_firewall` | Network firewall rules | Domain filtering, protocols, stateful/stateless rules |
| `aws_cloudwatch_log_group` | Logging infrastructure | Retention, encryption |
| `aws_subnet` | Network segmentation | Public/private subnets, AZ placement |
| `aws_route_table` | Traffic routing | Custom routes, gateway associations |
| `aws_vpc_endpoint` | Private AWS service access | Interface/Gateway endpoints, security groups |
| `aws_s3_bucket` | Log storage | Lifecycle policies, encryption |
| `aws_security_group` | Network access control | Ingress/egress rules, protocol filtering |
| `aws_flow_log` | Network traffic monitoring | CloudWatch/S3 destination, retention |

### Basic Example

```hcl
module "network_firewall" {
  source = "path/to/module"

  # Basic Configuration
  name_prefix = "basic-firewall"
  availability_zones = ["us-east-1a", "us-east-1b"]
  
  # VPC Configuration
  firewall_vpc_cidr = "10.100.0.0/16"
  firewall_public_subnets  = ["10.100.1.0/24", "10.100.2.0/24"]
  firewall_private_subnets = ["10.100.10.0/24", "10.100.11.0/24"]
  
  # Domain Blocking
  blocked_domains = [
    "malware.example.com",
    "phishing.example.com"
  ]
  
  # Logging Configuration
  enable_s3_logging = true
  enable_cloudwatch_logging = true
  log_retention_days = 30
  
  common_tags = {
    Environment = "development"
    Project     = "network-security"
  }
}
```

### Advanced Enterprise Example

```hcl
module "enterprise_network_firewall" {
  source = "path/to/module"

  # Enterprise Configuration
  name_prefix = "enterprise-firewall"
  availability_zones = ["us-east-1a", "us-east-1b", "us-east-1c"]
  
  # Advanced VPC Configuration
  firewall_vpc_cidr = "10.200.0.0/16"
  enable_ipv6 = true
  vpc_instance_tenancy = "default"
  
  # Transit Gateway Configuration
  transit_gateway_asn = 64513
  transit_gateway_multicast_support = "enable"
  transit_gateway_appliance_mode_support = "enable"
  
  # Advanced Firewall Configuration
  firewall_delete_protection = true
  firewall_policy_change_protection = true
  stateful_rule_order = "STRICT_ORDER"
  
  # Comprehensive Domain Blocking
  blocked_domains = [
    "malware.example.com",
    "phishing.example.com",
    "social-media.com",
    "gaming-sites.com"
  ]
  
  # Enterprise Logging
  enable_s3_lifecycle = true
  s3_transition_to_ia_days = 30
  s3_transition_to_glacier_days = 90
  log_retention_days = 2555 # 7 years for compliance
  
  # Security Configuration
  firewall_security_group_ingress_rules = [
    {
      from_port   = 443
      to_port     = 443
      protocol    = "tcp"
      cidr_blocks = ["10.0.0.0/8"]
      description = "HTTPS access from private networks"
    }
  ]
  
  common_tags = {
    Environment = "production"
    Compliance = "SOC2,HIPAA,PCI"
    DataClassification = "confidential"
  }
}
```

## 📚 Input Variables

### Required Variables

| Name | Description | Type | Default |
|------|-------------|------|---------|
| `name_prefix` | Prefix for all resource names | `string` | `"network-firewall"` |
| `availability_zones` | List of availability zones (min 2) | `list(string)` | `["us-east-1a", "us-east-1b"]` |
| `firewall_vpc_cidr` | CIDR block for firewall VPC | `string` | `"10.100.0.0/16"` |
| `firewall_public_subnets` | Public subnet CIDR blocks | `list(string)` | `["10.100.1.0/24", "10.100.2.0/24"]` |
| `firewall_private_subnets` | Private subnet CIDR blocks | `list(string)` | `["10.100.10.0/24", "10.100.11.0/24"]` |

### Transit Gateway Configuration

| Name | Description | Type | Default |
|------|-------------|------|---------|
| `transit_gateway_asn` | Private ASN for Transit Gateway | `number` | `64512` |
| `transit_gateway_auto_accept_shared_attachments` | Auto accept shared attachments | `string` | `"disable"` |
| `transit_gateway_default_route_table_association` | Default route table association | `string` | `"enable"` |
| `transit_gateway_default_route_table_propagation` | Default route table propagation | `string` | `"enable"` |
| `transit_gateway_dns_support` | DNS support | `string` | `"enable"` |
| `transit_gateway_vpn_ecmp_support` | VPN ECMP support | `string` | `"enable"` |
| `transit_gateway_multicast_support` | Multicast support | `string` | `"disable"` |
| `transit_gateway_appliance_mode_support` | Appliance mode support | `string` | `"disable"` |
| `transit_gateway_ipv6_support` | IPv6 support | `string` | `"disable"` |

### VPC Configuration

| Name | Description | Type | Default |
|------|-------------|------|---------|
| `enable_dns_hostnames` | Enable DNS hostnames | `bool` | `true` |
| `enable_dns_support` | Enable DNS support | `bool` | `true` |
| `vpc_instance_tenancy` | Instance tenancy | `string` | `"default"` |
| `vpc_ipv4_ipam_pool_id` | IPv4 IPAM pool ID | `string` | `null` |
| `vpc_ipv4_netmask_length` | IPv4 netmask length | `number` | `null` |
| `enable_ipv6` | Enable IPv6 support | `bool` | `false` |
| `firewall_public_subnet_ipv6_cidrs` | Public subnet IPv6 CIDRs | `list(string)` | `[]` |
| `firewall_private_subnet_ipv6_cidrs` | Private subnet IPv6 CIDRs | `list(string)` | `[]` |

### Network Firewall Configuration

| Name | Description | Type | Default |
|------|-------------|------|---------|
| `firewall_delete_protection` | Delete protection | `bool` | `false` |
| `firewall_policy_change_protection` | Policy change protection | `bool` | `false` |
| `firewall_subnet_change_protection` | Subnet change protection | `bool` | `false` |
| `enable_stateless_rules` | Enable stateless rules | `bool` | `true` |
| `enable_stateful_rules` | Enable stateful rules | `bool` | `true` |
| `enable_stateful_engine_options` | Enable stateful engine options | `bool` | `false` |
| `stateless_rule_priority` | Stateless rule priority | `number` | `1` |
| `stateful_rule_priority` | Stateful rule priority | `number` | `2` |
| `stateful_rule_order` | Stateful rule order | `string` | `"DEFAULT_ACTION_ORDER"` |
| `stateless_rule_actions` | Stateless rule actions | `list(string)` | `["aws:forward_to_sfe"]` |
| `stateless_rule_destination_cidr` | Stateless rule destination CIDR | `string` | `"0.0.0.0/0"` |
| `stateless_rule_source_cidr` | Stateless rule source CIDR | `string` | `"0.0.0.0/0"` |
| `stateless_rule_protocols` | Stateless rule protocols | `list(number)` | `[1, 6, 17]` |
| `stateful_rules_generated_type` | Stateful rules generated type | `string` | `"DENYLIST"` |
| `stateful_rules_target_types` | Stateful rules target types | `list(string)` | `["HTTP_HOST", "TLS_SNI"]` |
| `blocked_domains` | Domains to block | `list(string)` | `["malware.example.com"]` |
| `stateless_rule_capacity` | Stateless rule capacity | `number` | `100` |
| `stateful_rule_capacity` | Stateful rule capacity | `number` | `100` |

### Logging Configuration

| Name | Description | Type | Default |
|------|-------------|------|---------|
| `enable_network_firewall_logging` | Enable firewall logging | `bool` | `true` |
| `enable_s3_logging` | Enable S3 logging | `bool` | `true` |
| `enable_cloudwatch_logging` | Enable CloudWatch logging | `bool` | `true` |
| `log_retention_days` | Log retention days | `number` | `30` |
| `s3_log_prefix` | S3 log prefix | `string` | `"firewall-logs/"` |
| `s3_alert_log_prefix` | S3 alert log prefix | `string` | `"alert-logs/"` |

### S3 Configuration

| Name | Description | Type | Default |
|------|-------------|------|---------|
| `s3_bucket_encryption` | S3 bucket encryption | `string` | `"AES256"` |
| `s3_bucket_kms_key_id` | S3 bucket KMS key ID | `string` | `null` |
| `s3_bucket_key_enabled` | S3 bucket key enabled | `bool` | `true` |
| `s3_bucket_force_destroy` | S3 bucket force destroy | `bool` | `false` |
| `s3_bucket_versioning_status` | S3 bucket versioning status | `string` | `"Enabled"` |
| `s3_block_public_acls` | Block public ACLs | `bool` | `true` |
| `s3_block_public_policy` | Block public policy | `bool` | `true` |
| `s3_ignore_public_acls` | Ignore public ACLs | `bool` | `true` |
| `s3_restrict_public_buckets` | Restrict public buckets | `bool` | `true` |
| `enable_s3_lifecycle` | Enable S3 lifecycle | `bool` | `false` |
| `s3_transition_to_ia_days` | Transition to IA days | `number` | `0` |
| `s3_transition_to_glacier_days` | Transition to Glacier days | `number` | `0` |
| `s3_expiration_days` | S3 expiration days | `number` | `2555` |
| `s3_abort_incomplete_multipart_upload_days` | Abort incomplete multipart upload days | `number` | `7` |

### CloudWatch Configuration

| Name | Description | Type | Default |
|------|-------------|------|---------|
| `cloudwatch_kms_key_id` | CloudWatch KMS key ID | `string` | `null` |
| `enable_metric_filters` | Enable metric filters | `bool` | `false` |
| `cloudwatch_alert_pattern` | CloudWatch alert pattern | `string` | `"[timestamp, action=BLOCK, ...]"` |

### IAM Configuration

| Name | Description | Type | Default |
|------|-------------|------|---------|
| `iam_role_path` | IAM role path | `string` | `"/"` |
| `enable_advanced_permissions` | Enable advanced permissions | `bool` | `false` |

### Security Groups Configuration

| Name | Description | Type | Default |
|------|-------------|------|---------|
| `firewall_security_group_egress_cidrs` | Firewall security group egress CIDRs | `list(string)` | `["0.0.0.0/0"]` |
| `firewall_security_group_ingress_rules` | Firewall security group ingress rules | `list(object)` | `[]` |

### VPC Endpoints Configuration

| Name | Description | Type | Default |
|------|-------------|------|---------|
| `vpc_endpoint_services` | VPC endpoint services | `list(string)` | `["com.amazonaws.us-east-1.logs", "com.amazonaws.us-east-1.s3"]` |
| `vpc_endpoint_private_dns_enabled` | VPC endpoint private DNS enabled | `bool` | `true` |
| `vpc_endpoint_ip_address_type` | VPC endpoint IP address type | `string` | `"ipv4"` |

### VPC Flow Logs Configuration

| Name | Description | Type | Default |
|------|-------------|------|---------|
| `enable_flow_logs` | Enable VPC flow logs | `bool` | `true` |
| `flow_logs_traffic_type` | Flow logs traffic type | `string` | `"ALL"` |
| `flow_logs_retention_days` | Flow logs retention days | `number` | `30` |

## 📤 Outputs

| Name | Description |
|------|-------------|
| `transit_gateway_id` | Transit Gateway ID |
| `network_firewall_id` | Network Firewall ID |
| `firewall_vpc_id` | Firewall VPC ID |
| `firewall_logs_s3_bucket` | S3 bucket for firewall logs |
| `cloudwatch_log_group_name` | CloudWatch log group name |
| `firewall_policy_arn` | Network Firewall Policy ARN |
| `stateless_rule_group_arn` | Stateless Rule Group ARN |
| `stateful_rule_group_arn` | Stateful Rule Group ARN |
| `blocked_domains` | List of blocked domains |

## 🔒 Security Considerations

- **Network Segmentation**: Use separate VPCs for firewall infrastructure
- **Access Control**: Implement restrictive security groups
- **Encryption**: Enable encryption for all data at rest and in transit
- **Monitoring**: Enable comprehensive logging and monitoring
- **Compliance**: Configure appropriate retention policies for compliance requirements
- **Updates**: Regularly update firewall rules and policies
- **Backup**: Implement backup and disaster recovery procedures

## 💰 Cost Optimization

- **Log Retention**: Configure appropriate log retention periods
- **S3 Lifecycle**: Use S3 lifecycle policies to transition data to cheaper storage
- **Rule Capacity**: Optimize rule group capacities based on actual usage
- **Multi-AZ**: Use minimum required availability zones for your use case
- **Monitoring**: Use CloudWatch metrics to monitor costs

## 🚨 Important Notes

- **ASN Range**: Use private ASN range (64512-65534) for Transit Gateway
- **Subnet Requirements**: Ensure subnets are in different availability zones
- **Domain Lists**: Keep domain lists updated for effective filtering
- **Capacity Planning**: Monitor rule group capacities and adjust as needed
- **IPv6**: IPv6 support requires careful planning and testing
- **Compliance**: Ensure logging and retention meet compliance requirements

## 📁 Examples

See the `examples/` directory for complete working examples:

- **Basic Example**: Simple deployment with essential features
- **Advanced Example**: Enterprise-grade deployment with all features

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## 📄 License

This module is licensed under the MIT License. See the LICENSE file for details.

## 🆘 Support

For issues and questions:
- Create an issue in the repository
- Check the examples directory
- Review the documentation

## 📈 Version History

- **v2.0.0**: Enhanced with comprehensive customization options
- **v1.0.0**: Initial release with basic functionality