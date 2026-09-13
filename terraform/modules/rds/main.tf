terraform {
  required_version = ">= 1.5.0, < 2.0.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.80"
    }
  }
}

# Database Subnet Group (Private Database Subnets Only)
resource "aws_db_subnet_group" "postgres" {
  name        = "${var.project_name}-db-subnet-group-${var.environment}"
  subnet_ids  = var.database_subnet_ids
  description = "Isolated database subnet group for B-SEA PostgreSQL"

  tags = {
    Name = "${var.project_name}-db-subnet-group-${var.environment}"
  }
}

# PostgreSQL 16 Parameter Group enforcing TLS/SSL
resource "aws_db_parameter_group" "postgres16" {
  name        = "${var.project_name}-pg16-params-${var.environment}"
  family      = "postgres16"
  description = "B-SEA PostgreSQL 16 parameters enforcing TLS"

  parameter {
    name  = "rds.force_ssl"
    value = "1"
  }

  tags = {
    Name = "${var.project_name}-pg16-params-${var.environment}"
  }
}

# Standard AWS RDS PostgreSQL 16 Instance
# NOTE: NOT Aurora. Single-AZ and skip_final_snapshot are STAGING-ONLY configurations.
resource "aws_db_instance" "postgres" {
  identifier     = "${var.project_name}-postgres-${var.environment}"
  engine         = "postgres"
  engine_version = var.engine_version

  instance_class    = var.db_instance_class
  allocated_storage = var.db_allocated_storage
  storage_type      = "gp3"

  # AWS-managed storage encryption (Phase 3C-2 boundary; Customer KMS keys belong to Phase 3C-3)
  storage_encrypted = true

  db_name  = var.db_name
  username = var.db_username
  password = var.db_password
  port     = 5432

  db_subnet_group_name   = aws_db_subnet_group.postgres.name
  parameter_group_name   = aws_db_parameter_group.postgres16.name
  vpc_security_group_ids = [var.rds_sg_id]

  # Mandatory security isolation
  publicly_accessible = false

  # Staging-only availability & teardown settings
  multi_az            = false
  skip_final_snapshot = var.skip_final_snapshot
  deletion_protection = var.deletion_protection

  auto_minor_version_upgrade = true

  tags = {
    Name = "${var.project_name}-postgres-${var.environment}"
  }
}
