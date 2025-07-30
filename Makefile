# =============================================================================
# Makefile for AWS Network Firewall Terraform Module
# =============================================================================

.PHONY: help init plan apply destroy validate fmt lint clean test

# Default target
help:
	@echo "Available targets:"
	@echo "  init      - Initialize Terraform"
	@echo "  plan      - Create Terraform plan"
	@echo "  apply     - Apply Terraform configuration"
	@echo "  destroy   - Destroy Terraform resources"
	@echo "  validate  - Validate Terraform configuration"
	@echo "  fmt       - Format Terraform code"
	@echo "  lint      - Lint Terraform code with tflint"
	@echo "  clean     - Clean up temporary files"
	@echo "  test      - Run tests"
	@echo "  docs      - Generate documentation"

# Initialize Terraform
init:
	@echo "Initializing Terraform..."
	terraform init

# Create Terraform plan
plan:
	@echo "Creating Terraform plan..."
	terraform plan -out=tfplan

# Apply Terraform configuration
apply:
	@echo "Applying Terraform configuration..."
	terraform apply tfplan

# Destroy Terraform resources
destroy:
	@echo "Destroying Terraform resources..."
	terraform destroy

# Validate Terraform configuration
validate:
	@echo "Validating Terraform configuration..."
	terraform validate

# Format Terraform code
fmt:
	@echo "Formatting Terraform code..."
	terraform fmt -recursive

# Lint Terraform code
lint:
	@echo "Linting Terraform code..."
	@if command -v tflint >/dev/null 2>&1; then \
		tflint --init; \
		tflint; \
	else \
		echo "tflint not found. Install with: go install github.com/terraform-linters/tflint/cmd/tflint@latest"; \
	fi

# Clean up temporary files
clean:
	@echo "Cleaning up temporary files..."
	rm -f tfplan
	rm -rf .terraform
	rm -rf .terraform.lock.hcl

# Run tests
test:
	@echo "Running tests..."
	@if [ -d "test" ]; then \
		cd test && terraform init && terraform plan; \
	else \
		echo "No test directory found"; \
	fi

# Generate documentation
docs:
	@echo "Generating documentation..."
	@if command -v terraform-docs >/dev/null 2>&1; then \
		terraform-docs markdown table . > README.md.tmp; \
		echo "Documentation generated in README.md.tmp"; \
	else \
		echo "terraform-docs not found. Install with: go install github.com/terraform-docs/terraform-docs/cmd/terraform-docs@latest"; \
	fi

# Security scan
security-scan:
	@echo "Running security scan..."
	@if command -v terrascan >/dev/null 2>&1; then \
		terrascan scan -i terraform .; \
	else \
		echo "terrascan not found. Install with: curl -L \"\$$(curl -s https://api.github.com/repos/tenable/terrascan/releases/latest | grep -o -m 1 \"https://.*terrascan.*tar.gz\")\" | tar -xz terrascan && sudo mv terrascan /usr/local/bin/"; \
	fi

# Cost estimation
cost:
	@echo "Estimating costs..."
	@if command -v infracost >/dev/null 2>&1; then \
		infracost breakdown --path .; \
	else \
		echo "infracost not found. Install with: curl -fsSL https://raw.githubusercontent.com/infracost/infracost/master/scripts/install.sh | sh"; \
	fi

# Check for updates
check-updates:
	@echo "Checking for provider updates..."
	terraform init -upgrade

# Workspace management
workspace-dev:
	@echo "Switching to development workspace..."
	terraform workspace select dev || terraform workspace new dev

workspace-staging:
	@echo "Switching to staging workspace..."
	terraform workspace select staging || terraform workspace new staging

workspace-prod:
	@echo "Switching to production workspace..."
	terraform workspace select prod || terraform workspace new prod

# Example deployments
example-basic:
	@echo "Deploying basic example..."
	cd examples/basic && terraform init && terraform plan

example-advanced:
	@echo "Deploying advanced example..."
	cd examples/advanced && terraform init && terraform plan

# Backup and restore
backup:
	@echo "Creating backup of Terraform state..."
	@if [ -f terraform.tfstate ]; then \
		cp terraform.tfstate terraform.tfstate.backup.$$(date +%Y%m%d_%H%M%S); \
		echo "Backup created: terraform.tfstate.backup.$$(date +%Y%m%d_%H%M%S)"; \
	else \
		echo "No terraform.tfstate file found"; \
	fi

# Pre-commit hooks
pre-commit: fmt validate lint
	@echo "Pre-commit checks completed"

# CI/CD pipeline
ci: init validate fmt lint test
	@echo "CI pipeline completed successfully"

# Development setup
dev-setup:
	@echo "Setting up development environment..."
	@if ! command -v terraform >/dev/null 2>&1; then \
		echo "Installing Terraform..."; \
		curl -fsSL https://apt.releases.hashicorp.com/gpg | sudo apt-key add -; \
		sudo apt-add-repository "deb [arch=amd64] https://apt.releases.hashicorp.com $$(lsb_release -cs) main"; \
		sudo apt-get update && sudo apt-get install terraform; \
	fi
	@if ! command -v tflint >/dev/null 2>&1; then \
		echo "Installing tflint..."; \
		go install github.com/terraform-linters/tflint/cmd/tflint@latest; \
	fi
	@if ! command -v terrascan >/dev/null 2>&1; then \
		echo "Installing terrascan..."; \
		curl -L "$$(curl -s https://api.github.com/repos/tenable/terrascan/releases/latest | grep -o -m 1 "https://.*terrascan.*tar.gz")" | tar -xz terrascan && sudo mv terrascan /usr/local/bin/; \
	fi
	@echo "Development environment setup complete" 