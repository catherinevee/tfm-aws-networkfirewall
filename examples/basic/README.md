# Basic AWS Network Firewall Example

This example demonstrates a basic configuration of AWS Network Firewall with Transit Gateway integration.

## Features Demonstrated

- Basic VPC setup with public and private subnets
- Simple Network Firewall policy with domain filtering
- Basic logging configuration
- Essential tags for resource management

## Usage

To run this example:

```bash
terraform init
terraform plan
terraform apply
```

## Notes

- This example deploys resources into your AWS account. Make sure you understand the costs involved before deploying.
- The example uses default values for many optional parameters to show a minimal configuration.
- Adjust the CIDR ranges and availability zones according to your requirements.
