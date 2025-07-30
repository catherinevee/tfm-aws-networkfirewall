# AWS Network Firewall with Transit Gateway Traffic Inspection

A comprehensive Terraform module for deploying AWS Network Firewall with Transit Gateway traffic inspection architecture. This module provides a secure, scalable solution for inspecting and filtering network traffic across multiple VPCs.

## Architecture Overview

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   VPC A         │    │   Transit        │    │   VPC B         │
│   (Private)     │────│   Gateway        │────│   (Private)     │
└─────────────────┘    └──────────────────┘    └─────────────────┘
                              │
                              ▼
                       ┌──────────────────┐
                       │   Network        │
                       │   Firewall VPC   │
                       │                  │
                       │  ┌────────────┐  │
                       │  │ Network    │  │
                       │  │ Firewall   │  │
                       │  └────────────┘  │
                       └──────────────────┘
```

## Features

- **Transit Gateway**: Centralized network hub for connecting multiple VPCs
- **Network Firewall**: Stateful and stateless traffic inspection
- **High Availability**: Multi-AZ deployment with redundancy
- **Comprehensive Logging**: S3 and CloudWatch integration
- **Security Groups**: Proper network segmentation
- **VPC Endpoints**: Private connectivity to AWS services
- **IAM Integration**: Least privilege access controls

## Prerequisites

- Terraform >= 1.0
- AWS Provider >= 5.0
- AWS CLI configured with appropriate permissions
- At least 2 availability zones in your target region

## Usage

### Basic Example

```hcl
module "network_firewall" {
  source = "./tfm-aws-networkfirewall"

  name_prefix = "my-network-firewall"
  
  availability_zones = ["us-east-1a", "us-east-1b"]
  
  firewall_vpc_cidr = "10.100.0.0/16"
  firewall_public_subnets  = ["10.100.1.0/24", "10.100.2.0/24"]
  firewall_private_subnets = ["10.100.10.0/24", "10.100.11.0/24"]
  
  blocked_domains = [
    "malware.example.com",
    "phishing.example.com",
    "suspicious-site.com"
  ]
  
  common_tags = {
    Environment = "production"
    Project     = "security"
    Owner       = "security-team"
  }
}
```

### Advanced Example

```hcl
module "network_firewall" {
  source = "./tfm-aws-networkfirewall"

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
    "botnet-command.com"
  ]
  
  log_retention_days = 90
  
  vpc_endpoint_services = [
    "com.amazonaws.us-east-1.logs",
    "com.amazonaws.us-east-1.s3",
    "com.amazonaws.us-east-1.ec2",
    "com.amazonaws.us-east-1.ec2messages",
    "com.amazonaws.us-east-1.ssm",
    "com.amazonaws.us-east-1.ssmmessages"
  ]
  
  common_tags = {
    Environment = "production"
    Project     = "enterprise-security"
    Owner       = "security-team"
    CostCenter  = "security-ops"
    Compliance  = "sox-pci"
  }
}
```

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|:--------:|
| name_prefix | Prefix for all resource names | `string` | `"network-firewall"` | no |
| common_tags | Common tags for all resources | `map(string)` | `{}` | no |
| tgw_description | Transit Gateway description | `string` | `"Transit Gateway for Network Firewall Traffic Inspection"` | no |
| firewall_vpc_cidr | CIDR block for firewall VPC | `string` | `"10.100.0.0/16"` | no |
| availability_zones | List of availability zones | `list(string)` | `["us-east-1a", "us-east-1b"]` | no |
| firewall_public_subnets | Public subnet CIDR blocks | `list(string)` | `["10.100.1.0/24", "10.100.2.0/24"]` | no |
| firewall_private_subnets | Private subnet CIDR blocks | `list(string)` | `["10.100.10.0/24", "10.100.11.0/24"]` | no |
| blocked_domains | Domains to block | `list(string)` | `[]` | no |
| log_retention_days | CloudWatch log retention days | `number` | `30` | no |
| vpc_endpoint_services | VPC endpoint services | `list(string)` | `["com.amazonaws.us-east-1.logs", "com.amazonaws.us-east-1.s3"]` | no |

## Outputs

| Name | Description |
|------|-------------|
| transit_gateway_id | Transit Gateway ID |
| network_firewall_id | Network Firewall ID |
| firewall_vpc_id | Firewall VPC ID |
| firewall_logs_s3_bucket | S3 bucket for logs |
| cloudwatch_log_group_name | CloudWatch log group name |

## Network Firewall Rules

### Stateless Rules
- Default action: Forward to stateful engine
- Handles fragmented packets
- High-performance packet processing

### Stateful Rules
- Domain-based filtering
- HTTP and HTTPS inspection
- TLS/SSL traffic analysis
- Custom rule support

## Security Features

### Network Segmentation
- Isolated firewall VPC
- Public and private subnets
- Security groups with least privilege
- VPC endpoints for private connectivity

### Logging and Monitoring
- S3 bucket for long-term storage
- CloudWatch for real-time monitoring
- Flow logs for traffic analysis
- Alert logs for security events

### IAM Security
- Least privilege access
- Service-linked roles
- Encrypted storage
- Audit logging

## Best Practices

### Network Design
1. **Subnet Planning**: Use non-overlapping CIDR blocks
2. **AZ Distribution**: Deploy across multiple availability zones
3. **Route Tables**: Separate public and private traffic
4. **Security Groups**: Restrict access to necessary ports only

### Security Configuration
1. **Domain Filtering**: Regularly update blocked domain lists
2. **Log Retention**: Configure appropriate retention periods
3. **Encryption**: Enable encryption for all storage
4. **Monitoring**: Set up alerts for security events

### Operational Considerations
1. **Backup**: Regular configuration backups
2. **Updates**: Keep firewall rules current
3. **Testing**: Validate rules in non-production first
4. **Documentation**: Maintain rule documentation

## Troubleshooting

### Common Issues

1. **Firewall Not Starting**
   - Check IAM permissions
   - Verify subnet configurations
   - Review CloudWatch logs

2. **Traffic Not Flowing**
   - Verify route table configurations
   - Check security group rules
   - Validate Transit Gateway attachments

3. **Logging Issues**
   - Confirm S3 bucket permissions
   - Check CloudWatch log group
   - Verify IAM role policies

### Debug Commands

```bash
# Check firewall status
aws network-firewall describe-firewall --firewall-name <name>

# View firewall logs
aws logs describe-log-streams --log-group-name /aws/networkfirewall/<name>

# Check Transit Gateway routes
aws ec2 describe-transit-gateway-route-tables --transit-gateway-id <tgw-id>
```

## Cost Optimization

### Resource Sizing
- Start with minimal rule capacity
- Scale based on traffic patterns
- Use appropriate instance types

### Storage Optimization
- Configure log retention policies
- Use S3 lifecycle rules
- Compress logs when possible

### Network Optimization
- Use VPC endpoints for AWS services
- Optimize route table configurations
- Monitor data transfer costs

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## License

This module is licensed under the MIT License. See LICENSE file for details.

## Support

For issues and questions:
- Create an issue in the repository
- Check the troubleshooting section
- Review AWS Network Firewall documentation

## References

- [AWS Network Firewall Documentation](https://docs.aws.amazon.com/network-firewall/)
- [AWS Transit Gateway Documentation](https://docs.aws.amazon.com/vpc/latest/tgw/)
- [Terraform AWS Provider](https://registry.terraform.io/providers/hashicorp/aws/latest/docs)