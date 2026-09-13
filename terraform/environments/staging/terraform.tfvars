# ── Staging Environment Non-Sensitive Variables ──────────────────────────────
# NOTE: Zero secrets or passwords may be placed in this file.
# Database and Redis credentials are generated dynamically via high-entropy
# random_password resources and stored directly into AWS Secrets Manager.

aws_region   = "ap-south-1"
environment  = "staging"
project_name = "bsea"

# Networking
vpc_cidr = "10.0.0.0/16"

# Database (AWS RDS PostgreSQL 16 — Standard RDS, NOT Aurora)
db_name              = "bsea"
db_username          = "bsea_admin"
db_instance_class    = "db.t4g.medium"
db_allocated_storage = 20

# Cache (Amazon ElastiCache Redis 7)
redis_node_type = "cache.t4g.micro"

# Compute (ECS Fargate)
backend_container_image = "123456789012.dkr.ecr.ap-south-1.amazonaws.com/bsea-backend-staging:latest"
task_cpu                = 512
task_memory             = 1024
desired_task_count      = 2
min_task_count          = 2
max_task_count          = 4

# Ingress (ALB / ACM / CloudFront)
# If a validated ACM certificate exists, set its ARN here.
# Left empty for staging dry-runs and automated lint verification.
acm_certificate_arn = ""

# Dedicated API domain for CloudFront HTTPS origin (Option A).
# e.g. "api-staging.bsea.gov.in" matching ACM certificate subject name.
# When empty (""), CloudFront falls back to ALB DNS name with runtime status:
# CLOUDFRONT_TO_ALB_HTTPS_RUNTIME_VALIDATION_PENDING (Option B).
custom_api_domain = ""

# Cryptographic provider for staging ECS Fargate workload
kms_provider = "aws"
