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

  # ── REMOTE STATE ARCHITECTURE SPECIFICATION ─────────────────────────────────
  # In an active deployment pipeline, state MUST be stored remotely with encryption,
  # versioning, and locking enabled.
  #
  # APPROVED ARCHITECTURE: Terraform Native S3 State Locking (Terraform >= 1.10)
  # Uses native S3 .tflock state locking (use_lockfile = true).
  # Eliminates DynamoDB dependency (DynamoDB locking is deprecated / legacy only).
  #
  # S3 State Bucket Architecture:
  #   ├── SSE-S3 / KMS Encryption
  #   ├── Object Versioning
  #   ├── Block Public Access (all 4 settings enabled)
  #   ├── Restricted IAM Access Policies
  #   └── Terraform Native .tflock State Locking
  #
  # Bootstrap prerequisite:
  #   - S3 Bucket: bsea-terraform-state-<account_id>-staging (SSE-S3, Public Access Block, Versioning)
  #
  # backend "s3" {
  #   bucket       = "bsea-terraform-state-staging"
  #   key          = "staging/terraform.tfstate"
  #   region       = "ap-south-1"
  #   encrypt      = true
  #   use_lockfile = true
  # }
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project     = "B-SEA"
      Environment = var.environment
      ManagedBy   = "Terraform"
      Phase       = "3C-2"
    }
  }
}

provider "random" {}
