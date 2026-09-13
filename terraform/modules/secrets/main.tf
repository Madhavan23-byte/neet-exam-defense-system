terraform {
  required_version = ">= 1.5.0, < 2.0.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.80, < 7.0.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.6"
    }
  }
}

# ── 1. Database Master Credentials ───────────────────────────────────────────
# NOTE ON TERRAFORM STATE SECURITY:
# random_password values exist in plaintext inside the encrypted Terraform state file.
# Remote state protection (S3 SSE-S3/KMS, strict IAM, state locking) is MANDATORY.
# Generated passwords are never exposed through Terraform outputs.
resource "random_password" "db_master" {
  length  = 24
  special = false # Letters and numbers only to prevent URI escaping issues in connection strings
}

resource "aws_secretsmanager_secret" "db_credentials" {
  name                    = "${var.project_name}-db-credentials-${var.environment}"
  description             = "B-SEA Database Master Credentials (managed by RDS Proxy & ECS)"
  recovery_window_in_days = var.recovery_window_in_days

  tags = {
    Name = "${var.project_name}-db-credentials-${var.environment}"
  }
}

# RDS Proxy mandates that Secrets Manager secrets contain 'username' and 'password' keys
resource "aws_secretsmanager_secret_version" "db_credentials" {
  secret_id = aws_secretsmanager_secret.db_credentials.id
  secret_string = jsonencode({
    username = var.db_username
    password = random_password.db_master.result
    engine   = "postgres"
    port     = 5432
    dbname   = var.db_name
  })
}

# ── 2. Redis AUTH Token ───────────────────────────────────────────────────────
resource "random_password" "redis_auth" {
  length  = 32
  special = false
}

resource "aws_secretsmanager_secret" "redis_auth" {
  name                    = "${var.project_name}-redis-auth-${var.environment}"
  description             = "B-SEA ElastiCache Redis AUTH token for distributed rate limiting"
  recovery_window_in_days = var.recovery_window_in_days

  tags = {
    Name = "${var.project_name}-redis-auth-${var.environment}"
  }
}

resource "aws_secretsmanager_secret_version" "redis_auth" {
  secret_id = aws_secretsmanager_secret.redis_auth.id
  secret_string = jsonencode({
    auth_token = random_password.redis_auth.result
  })
}

# ── 3. Application JWT Secret (Staging Baseline) ──────────────────────────────
resource "random_password" "jwt_secret" {
  length  = 48
  special = false
}

resource "aws_secretsmanager_secret" "jwt_secret" {
  name                    = "${var.project_name}-jwt-secret-${var.environment}"
  description             = "B-SEA JWT Signing Secret (Placeholder for staging environment)"
  recovery_window_in_days = var.recovery_window_in_days

  tags = {
    Name = "${var.project_name}-jwt-secret-${var.environment}"
  }
}

resource "aws_secretsmanager_secret_version" "jwt_secret" {
  secret_id = aws_secretsmanager_secret.jwt_secret.id
  secret_string = jsonencode({
    jwt_secret_key = random_password.jwt_secret.result
  })
}
