terraform {
  required_version = ">= 1.5.0, < 2.0.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.80, < 7.0.0"
    }
  }
}

data "aws_caller_identity" "current" {}

# ── 1. Symmetric Encryption KMS Key (AES-256 Envelope Encryption) ──────────────
# Used to generate 256-bit data keys for AES-256-GCM authenticated envelope encryption.
# AWS KMS manages automatic annual rotation of backing key material.
resource "aws_kms_key" "symmetric_encryption" {
  description              = "B-SEA Symmetric Encryption Key (AES-256 Envelope Encryption) [${var.environment}]"
  customer_master_key_spec = "SYMMETRIC_DEFAULT"
  key_usage                = "ENCRYPT_DECRYPT"
  enable_key_rotation      = true
  deletion_window_in_days  = 30

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "EnableAccountRootAdministration"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Action = [
          "kms:Create*",
          "kms:Describe*",
          "kms:Enable*",
          "kms:List*",
          "kms:Put*",
          "kms:Update*",
          "kms:Revoke*",
          "kms:Disable*",
          "kms:Get*",
          "kms:Delete*",
          "kms:TagResource",
          "kms:UntagResource",
          "kms:ScheduleKeyDeletion",
          "kms:CancelKeyDeletion"
        ]
        Resource = "*"
      },
      {
        Sid    = "AllowECSTaskEnvelopeEncryption"
        Effect = "Allow"
        Principal = {
          AWS = var.ecs_task_role_arn
        }
        Action = [
          "kms:GenerateDataKey",
          "kms:Decrypt",
          "kms:DescribeKey"
        ]
        Resource = "*"
      }
    ]
  })

  tags = {
    Name        = "${var.project_name}-encryption-key-${var.environment}"
    Environment = var.environment
    KeyType     = "Symmetric"
    Rotation    = "Automatic"
  }
}

resource "aws_kms_alias" "symmetric_encryption" {
  name          = "alias/${var.project_name}-encryption-${var.environment}"
  target_key_id = aws_kms_key.symmetric_encryption.key_id
}

# ── 2. Asymmetric Ed25519 Signing KMS Key ─────────────────────────────────────
# Used for examination authorization signatures, blueprint integrity seals, and break-glass statements.
# Private signing key remains strictly inside the AWS KMS HSM perimeter.
# Asymmetric keys do NOT support AWS automatic key rotation; rotation is manual.
resource "aws_kms_key" "asymmetric_signing" {
  description              = "B-SEA Asymmetric Ed25519 Signing Key [${var.environment}]"
  customer_master_key_spec = "ECC_NIST_EDWARDS25519"
  key_usage                = "SIGN_VERIFY"
  enable_key_rotation      = false
  deletion_window_in_days  = 30

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "EnableAccountRootAdministration"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Action = [
          "kms:Create*",
          "kms:Describe*",
          "kms:Enable*",
          "kms:List*",
          "kms:Put*",
          "kms:Update*",
          "kms:Revoke*",
          "kms:Disable*",
          "kms:Get*",
          "kms:Delete*",
          "kms:TagResource",
          "kms:UntagResource",
          "kms:ScheduleKeyDeletion",
          "kms:CancelKeyDeletion"
        ]
        Resource = "*"
      },
      {
        Sid    = "AllowECSTaskSigning"
        Effect = "Allow"
        Principal = {
          AWS = var.ecs_task_role_arn
        }
        Action = [
          "kms:Sign",
          "kms:DescribeKey"
        ]
        Resource = "*"
      },
      {
        Sid    = "AllowECSTaskPublicKeyRetrieval"
        Effect = "Allow"
        Principal = {
          AWS = var.ecs_task_role_arn
        }
        Action = [
          "kms:GetPublicKey",
          "kms:DescribeKey"
        ]
        Resource = "*"
      }
    ]
  })

  tags = {
    Name        = "${var.project_name}-signing-key-${var.environment}"
    Environment = var.environment
    KeyType     = "Asymmetric-Ed25519"
    Rotation    = "Manual"
  }
}

resource "aws_kms_alias" "asymmetric_signing" {
  name          = "alias/${var.project_name}-signing-${var.environment}"
  target_key_id = aws_kms_key.asymmetric_signing.key_id
}
