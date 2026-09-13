terraform {
  required_version = ">= 1.5.0, < 2.0.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.80, < 7.0.0"
    }
  }
}

# ── 1. Application Load Balancer (ALB) Security Group ────────────────────────
resource "aws_security_group" "alb" {
  name        = "${var.project_name}-alb-sg-${var.environment}"
  description = "Controls public inbound traffic to the Application Load Balancer"
  vpc_id      = var.vpc_id

  tags = {
    Name = "${var.project_name}-alb-sg-${var.environment}"
  }
}

resource "aws_vpc_security_group_ingress_rule" "alb_http" {
  security_group_id = aws_security_group.alb.id
  description       = "Allow inbound HTTP for redirection to HTTPS"
  cidr_ipv4         = "0.0.0.0/0"
  from_port         = 80
  to_port           = 80
  ip_protocol       = "tcp"
}

resource "aws_vpc_security_group_ingress_rule" "alb_https" {
  security_group_id = aws_security_group.alb.id
  description       = "Allow inbound HTTPS from public internet"
  cidr_ipv4         = "0.0.0.0/0"
  from_port         = 443
  to_port           = 443
  ip_protocol       = "tcp"
}

resource "aws_vpc_security_group_egress_rule" "alb_to_ecs" {
  security_group_id            = aws_security_group.alb.id
  description                  = "Forward traffic only to ECS backend container tasks on port 8000"
  referenced_security_group_id = aws_security_group.ecs.id
  from_port                    = 8000
  to_port                      = 8000
  ip_protocol                  = "tcp"
}

# ── 2. ECS Fargate Backend Security Group ────────────────────────────────────
resource "aws_security_group" "ecs" {
  name        = "${var.project_name}-ecs-sg-${var.environment}"
  description = "Controls ingress and egress for ECS Fargate backend tasks"
  vpc_id      = var.vpc_id

  tags = {
    Name = "${var.project_name}-ecs-sg-${var.environment}"
  }
}

resource "aws_vpc_security_group_ingress_rule" "ecs_from_alb" {
  security_group_id            = aws_security_group.ecs.id
  description                  = "Allow inbound traffic strictly from ALB on port 8000"
  referenced_security_group_id = aws_security_group.alb.id
  from_port                    = 8000
  to_port                      = 8000
  ip_protocol                  = "tcp"
}

resource "aws_vpc_security_group_egress_rule" "ecs_to_rds_proxy" {
  security_group_id            = aws_security_group.ecs.id
  description                  = "Allow outbound connection to RDS Proxy on port 5432 (Direct RDS blocked)"
  referenced_security_group_id = aws_security_group.rds_proxy.id
  from_port                    = 5432
  to_port                      = 5432
  ip_protocol                  = "tcp"
}

resource "aws_vpc_security_group_egress_rule" "ecs_to_redis" {
  security_group_id            = aws_security_group.ecs.id
  description                  = "Allow outbound connection to ElastiCache Redis on port 6379"
  referenced_security_group_id = aws_security_group.redis.id
  from_port                    = 6379
  to_port                      = 6379
  ip_protocol                  = "tcp"
}

resource "aws_vpc_security_group_egress_rule" "ecs_https_outbound" {
  security_group_id = aws_security_group.ecs.id
  description       = "Allow outbound HTTPS via NAT for ECR, Secrets Manager, and CloudWatch logs"
  cidr_ipv4         = "0.0.0.0/0"
  from_port         = 443
  to_port           = 443
  ip_protocol       = "tcp"
}

# ── 3. RDS Proxy Security Group ──────────────────────────────────────────────
resource "aws_security_group" "rds_proxy" {
  name        = "${var.project_name}-rds-proxy-sg-${var.environment}"
  description = "Controls traffic to AWS RDS Proxy"
  vpc_id      = var.vpc_id

  tags = {
    Name = "${var.project_name}-rds-proxy-sg-${var.environment}"
  }
}

resource "aws_vpc_security_group_ingress_rule" "rds_proxy_from_ecs" {
  security_group_id            = aws_security_group.rds_proxy.id
  description                  = "Allow PostgreSQL inbound strictly from ECS tasks"
  referenced_security_group_id = aws_security_group.ecs.id
  from_port                    = 5432
  to_port                      = 5432
  ip_protocol                  = "tcp"
}

resource "aws_vpc_security_group_egress_rule" "rds_proxy_to_rds" {
  security_group_id            = aws_security_group.rds_proxy.id
  description                  = "Allow PostgreSQL outbound to authoritative RDS instance"
  referenced_security_group_id = aws_security_group.rds.id
  from_port                    = 5432
  to_port                      = 5432
  ip_protocol                  = "tcp"
}

# ── 4. RDS PostgreSQL Security Group ─────────────────────────────────────────
resource "aws_security_group" "rds" {
  name        = "${var.project_name}-rds-sg-${var.environment}"
  description = "Controls traffic to RDS PostgreSQL instance (Strictly Proxy only)"
  vpc_id      = var.vpc_id

  tags = {
    Name = "${var.project_name}-rds-sg-${var.environment}"
  }
}

# CRITICAL SECURITY INVARIANT: ECS is NOT permitted direct ingress to RDS.
# Ingress is allowed strictly from RDS Proxy SG.
resource "aws_vpc_security_group_ingress_rule" "rds_from_proxy_only" {
  security_group_id            = aws_security_group.rds.id
  description                  = "Allow PostgreSQL inbound strictly from RDS Proxy"
  referenced_security_group_id = aws_security_group.rds_proxy.id
  from_port                    = 5432
  to_port                      = 5432
  ip_protocol                  = "tcp"
}

# ── 5. ElastiCache Redis Security Group ───────────────────────────────────────
resource "aws_security_group" "redis" {
  name        = "${var.project_name}-redis-sg-${var.environment}"
  description = "Controls traffic to ElastiCache Redis replication group"
  vpc_id      = var.vpc_id

  tags = {
    Name = "${var.project_name}-redis-sg-${var.environment}"
  }
}

resource "aws_vpc_security_group_ingress_rule" "redis_from_ecs_only" {
  security_group_id            = aws_security_group.redis.id
  description                  = "Allow Redis TLS inbound strictly from ECS backend tasks"
  referenced_security_group_id = aws_security_group.ecs.id
  from_port                    = 6379
  to_port                      = 6379
  ip_protocol                  = "tcp"
}
