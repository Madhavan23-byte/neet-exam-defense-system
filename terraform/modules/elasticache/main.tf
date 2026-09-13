terraform {
  required_version = ">= 1.5.0, < 2.0.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.80"
    }
  }
}

# Subnet Group for ElastiCache (Private Database Subnets Only)
resource "aws_elasticache_subnet_group" "redis" {
  name        = "${var.project_name}-redis-subnet-group-${var.environment}"
  subnet_ids  = var.database_subnet_ids
  description = "Subnet group for B-SEA distributed rate limiting Redis"

  tags = {
    Name = "${var.project_name}-redis-subnet-group-${var.environment}"
  }
}

# Parameter Group for Redis OSS 7
resource "aws_elasticache_parameter_group" "redis7" {
  name        = "${var.project_name}-redis7-params-${var.environment}"
  family      = "redis7"
  description = "Parameter group for Redis 7 with cluster mode disabled"

  tags = {
    Name = "${var.project_name}-redis7-params-${var.environment}"
  }
}

# ElastiCache Redis 7 Replication Group
# NOTE: Single primary node is a STAGING-ONLY configuration.
# Production requires Multi-AZ with automatic failover enabled.
resource "aws_elasticache_replication_group" "redis" {
  replication_group_id = "${var.project_name}-redis-${var.environment}"
  description          = "B-SEA distributed rate limiting and ephemeral cache"
  engine               = "redis"
  engine_version       = "7.1"
  node_type            = var.redis_node_type
  num_cache_clusters   = 1 # Single primary node for staging
  port                 = 6379

  subnet_group_name    = aws_elasticache_subnet_group.redis.name
  parameter_group_name = aws_elasticache_parameter_group.redis7.name
  security_group_ids   = [var.redis_sg_id]

  # MANDATORY SECURITY INVARIANTS:
  transit_encryption_enabled = true # In-transit TLS enforcement
  at_rest_encryption_enabled = true # Volume encryption at rest
  auth_token                 = var.redis_auth_token

  # Automatic failover disabled because single node in staging
  automatic_failover_enabled = false
  apply_immediately          = true

  tags = {
    Name = "${var.project_name}-redis-${var.environment}"
  }
}
