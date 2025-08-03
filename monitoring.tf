# ==============================================================================
# Monitoring Configuration
# ==============================================================================

resource "aws_cloudwatch_log_group" "firewall" {
  count             = var.monitoring_config.enable_cloudwatch ? 1 : 0
  name              = "/aws/network-firewall/${var.name_prefix}"
  retention_in_days = var.monitoring_config.retention_days

  tags = merge(
    var.common_tags,
    {
      Name = "${var.name_prefix}-firewall-logs"
      Type = "log-group"
      Component = "monitoring"
    }
  )
}

resource "aws_flow_log" "vpc" {
  count           = var.monitoring_config.enable_cloudwatch ? 1 : 0
  log_destination = aws_cloudwatch_log_group.firewall[0].arn
  iam_role_arn    = aws_iam_role.flow_logs[0].arn
  vpc_id          = aws_vpc.firewall.id
  traffic_type    = "ALL"

  tags = merge(
    var.common_tags,
    {
      Name = "${var.name_prefix}-vpc-flow-logs"
      Type = "flow-log"
      Component = "monitoring"
    }
  )
}

resource "aws_iam_role" "flow_logs" {
  count = var.monitoring_config.enable_cloudwatch ? 1 : 0
  name  = "${var.name_prefix}-flow-logs-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "vpc-flow-logs.amazonaws.com"
        }
      }
    ]
  })

  tags = merge(
    var.common_tags,
    {
      Name = "${var.name_prefix}-flow-logs-role"
      Type = "iam-role"
      Component = "monitoring"
    }
  )
}
