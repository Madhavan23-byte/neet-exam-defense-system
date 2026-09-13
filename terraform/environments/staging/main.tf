# ── 1. Networking (Dedicated VPC across 2 dynamic AZs) ────────────────────────
module "vpc" {
  source = "../../modules/vpc"

  project_name = var.project_name
  environment  = var.environment
  vpc_cidr     = var.vpc_cidr
}

# ── 2. Security Groups (Strict Chaining Architecture) ─────────────────────────
module "security_groups" {
  source = "../../modules/security_groups"

  project_name = var.project_name
  environment  = var.environment
  vpc_id       = module.vpc.vpc_id
}

# ── 3. Secrets Manager (High-Entropy Credentials) ─────────────────────────────
module "secrets" {
  source = "../../modules/secrets"

  project_name            = var.project_name
  environment             = var.environment
  db_username             = var.db_username
  db_name                 = var.db_name
  recovery_window_in_days = 0 # Immediate deletion for staging teardown
}

# ── 4. IAM Roles & Least-Privilege Policies ───────────────────────────────────
module "iam" {
  source = "../../modules/iam"

  project_name     = var.project_name
  environment      = var.environment
  db_secret_arn    = module.secrets.db_secret_arn
  redis_secret_arn = module.secrets.redis_secret_arn
  jwt_secret_arn   = module.secrets.jwt_secret_arn
}

# ── 5. Private ECR Repository for Backend Container ───────────────────────────
module "ecr" {
  source = "../../modules/ecr"

  project_name = var.project_name
  environment  = var.environment
  force_delete = true # Staging teardown-friendly
}

# ── 6. Authoritative RDS PostgreSQL 16 (Standard RDS — NOT Aurora) ────────────
module "rds" {
  source = "../../modules/rds"

  project_name         = var.project_name
  environment          = var.environment
  database_subnet_ids  = module.vpc.database_subnet_ids
  rds_sg_id            = module.security_groups.rds_sg_id
  db_name              = var.db_name
  db_username          = var.db_username
  db_password          = module.secrets.db_master_password
  db_instance_class    = var.db_instance_class
  db_allocated_storage = var.db_allocated_storage
  skip_final_snapshot  = true  # Staging teardown-friendly
  deletion_protection  = false # Staging teardown-friendly
}

# ── 7. AWS RDS Proxy (Connection Lifecycle Management) ────────────────────────
module "rds_proxy" {
  source = "../../modules/rds_proxy"

  project_name        = var.project_name
  environment         = var.environment
  database_subnet_ids = module.vpc.database_subnet_ids
  rds_proxy_sg_id     = module.security_groups.rds_proxy_sg_id
  rds_proxy_role_arn  = module.iam.rds_proxy_role_arn
  db_secret_arn       = module.secrets.db_secret_arn
  db_instance_id      = module.rds.db_instance_id
}

# ── 8. Amazon ElastiCache Redis 7 (Distributed Rate Limiting) ─────────────────
module "elasticache" {
  source = "../../modules/elasticache"

  project_name        = var.project_name
  environment         = var.environment
  database_subnet_ids = module.vpc.database_subnet_ids
  redis_sg_id         = module.security_groups.redis_sg_id
  redis_node_type     = var.redis_node_type
  redis_auth_token    = module.secrets.redis_auth_token
}

# ── 9. Application Load Balancer & AWS WAFv2 Ingress ──────────────────────────
module "alb" {
  source = "../../modules/alb"

  project_name               = var.project_name
  environment                = var.environment
  vpc_id                     = module.vpc.vpc_id
  public_subnet_ids          = module.vpc.public_subnet_ids
  alb_sg_id                  = module.security_groups.alb_sg_id
  acm_certificate_arn        = var.acm_certificate_arn
  enable_deletion_protection = false # Staging teardown-friendly
}

# ── 10. ECS Fargate Cluster & Service (Backend Workload) ──────────────────────
module "ecs" {
  source = "../../modules/ecs"

  project_name            = var.project_name
  environment             = var.environment
  aws_region              = var.aws_region
  private_app_subnet_ids  = module.vpc.private_app_subnet_ids
  ecs_sg_id               = module.security_groups.ecs_sg_id
  target_group_arn        = module.alb.target_group_arn
  ecs_execution_role_arn  = module.iam.ecs_execution_role_arn
  ecs_task_role_arn       = module.iam.ecs_task_role_arn
  backend_container_image = var.backend_container_image
  task_cpu                = var.task_cpu
  task_memory             = var.task_memory
  desired_count           = var.desired_task_count
  min_count               = var.min_task_count
  max_count               = var.max_task_count
  log_retention_days      = 30

  # Internal network endpoints & secrets
  rds_proxy_endpoint = module.rds_proxy.proxy_endpoint
  db_name            = var.db_name
  db_username        = var.db_username
  db_secret_arn      = module.secrets.db_secret_arn
  redis_endpoint     = module.elasticache.primary_endpoint_address
  redis_port         = module.elasticache.port
  redis_secret_arn   = module.secrets.redis_secret_arn
  jwt_secret_arn     = module.secrets.jwt_secret_arn
}

# ── 11. S3 Frontend Hosting & CloudFront Edge Distribution ────────────────────
module "s3_frontend" {
  source = "../../modules/s3_frontend"

  project_name      = var.project_name
  environment       = var.environment
  alb_dns_name      = module.alb.alb_dns_name
  custom_api_domain = var.custom_api_domain
  force_destroy     = true # Staging teardown-friendly
}
