terraform {
  required_version = ">= 1.5.0, < 2.0.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.80"
    }
  }
}

# AWS RDS Proxy for Connection Lifecycle and Multi-Worker Pooling
resource "aws_db_proxy" "proxy" {
  name                   = "${var.project_name}-rds-proxy-${var.environment}"
  engine_family          = "POSTGRESQL"
  role_arn               = var.rds_proxy_role_arn
  vpc_subnet_ids         = var.database_subnet_ids
  vpc_security_group_ids = [var.rds_proxy_sg_id]

  # Mandatory TLS enforcement
  require_tls         = true
  idle_client_timeout = 1800
  debug_logging       = false

  # Authenticate against PostgreSQL using Secrets Manager master secret
  auth {
    auth_scheme = "SECRETS"
    secret_arn  = var.db_secret_arn
    iam_auth    = "DISABLED" # Conservative approved model (No end-to-end IAM DB auth in Phase 3C-2)
  }

  tags = {
    Name = "${var.project_name}-rds-proxy-${var.environment}"
  }
}

# RDS Proxy Default Target Group for Connection Pooling
resource "aws_db_proxy_default_target_group" "default" {
  db_proxy_name = aws_db_proxy.proxy.name

  connection_pool_config {
    connection_borrow_timeout    = 120
    max_connections_percent      = 90
    max_idle_connections_percent = 50
  }
}

# RDS Proxy Target Registration binding the authoritative RDS PostgreSQL instance
resource "aws_db_proxy_target" "target" {
  db_proxy_name          = aws_db_proxy.proxy.name
  target_group_name      = aws_db_proxy_default_target_group.default.name
  db_instance_identifier = var.db_instance_id
}
