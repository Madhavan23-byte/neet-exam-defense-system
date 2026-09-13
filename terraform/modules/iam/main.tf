terraform {
  required_version = ">= 1.5.0, < 2.0.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.80, < 7.0.0"
    }
  }
}

# ── 1. ECS Task Execution Role ───────────────────────────────────────────────
# Used by the ECS container agent to pull images, send logs, and fetch Secrets Manager secrets.
resource "aws_iam_role" "ecs_execution" {
  name        = "${var.project_name}-ecs-execution-role-${var.environment}"
  description = "Execution role for ECS Fargate to pull images and resolve secrets"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ecs-tasks.amazonaws.com"
        }
      }
    ]
  })

  tags = {
    Name = "${var.project_name}-ecs-execution-role-${var.environment}"
  }
}

resource "aws_iam_role_policy_attachment" "ecs_execution_standard" {
  role       = aws_iam_role.ecs_execution.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

resource "aws_iam_policy" "ecs_secrets_access" {
  name        = "${var.project_name}-ecs-secrets-policy-${var.environment}"
  description = "Grants ECS Execution Role permission to retrieve B-SEA application secrets"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "secretsmanager:GetSecretValue"
        ]
        Resource = [
          var.db_secret_arn,
          var.redis_secret_arn,
          var.jwt_secret_arn
        ]
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "ecs_secrets" {
  role       = aws_iam_role.ecs_execution.name
  policy_arn = aws_iam_policy.ecs_secrets_access.arn
}

# ── 2. ECS Task Role (Runtime Application Identity) ──────────────────────────
# Used by the running Python FastAPI process. Least-privilege: zero infra admin.
resource "aws_iam_role" "ecs_task" {
  name        = "${var.project_name}-ecs-task-role-${var.environment}"
  description = "Runtime application identity for B-SEA backend container"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ecs-tasks.amazonaws.com"
        }
      }
    ]
  })

  tags = {
    Name = "${var.project_name}-ecs-task-role-${var.environment}"
  }
}

# ── 3. RDS Proxy Authentication Role ─────────────────────────────────────────
# Allows RDS Proxy to assume role and read DB master credentials from Secrets Manager.
resource "aws_iam_role" "rds_proxy" {
  name        = "${var.project_name}-rds-proxy-role-${var.environment}"
  description = "Allows RDS Proxy to retrieve target database credentials from Secrets Manager"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "rds.amazonaws.com"
        }
      }
    ]
  })

  tags = {
    Name = "${var.project_name}-rds-proxy-role-${var.environment}"
  }
}

resource "aws_iam_policy" "rds_proxy_secrets" {
  name        = "${var.project_name}-rds-proxy-secrets-policy-${var.environment}"
  description = "Permits RDS Proxy to read database master secret"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "secretsmanager:GetSecretValue"
        ]
        Resource = [
          var.db_secret_arn
        ]
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "rds_proxy_secrets" {
  role       = aws_iam_role.rds_proxy.name
  policy_arn = aws_iam_policy.rds_proxy_secrets.arn
}

# ── 4. ECS Task Role KMS Runtime Cryptographic Policy ─────────────────────────
# Least-privilege runtime policy granting ONLY actions used by the application:
# - Symmetric: GenerateDataKey and Decrypt (for envelope encryption)
# - Asymmetric: Sign and GetPublicKey (for Ed25519 signing and offline verification)
# Zero KMS administration, rotation, or deletion capabilities are granted.
resource "aws_iam_policy" "ecs_kms_crypto" {
  name        = "${var.project_name}-ecs-kms-crypto-policy-${var.environment}"
  description = "Runtime KMS cryptographic operations for B-SEA ECS task (encryption, decryption, signing, public-key retrieval)"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "SymmetricEnvelopeCrypto"
        Effect = "Allow"
        Action = [
          "kms:GenerateDataKey",
          "kms:Decrypt",
          "kms:DescribeKey"
        ]
        Resource = [
          var.kms_encryption_key_arn
        ]
      },
      {
        Sid    = "AsymmetricEd25519SigningAndVerification"
        Effect = "Allow"
        Action = [
          "kms:Sign",
          "kms:GetPublicKey",
          "kms:DescribeKey"
        ]
        Resource = [
          var.kms_signing_key_arn
        ]
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "ecs_kms_crypto" {
  role       = aws_iam_role.ecs_task.name
  policy_arn = aws_iam_policy.ecs_kms_crypto.arn
}
