# ── General Configuration ────────────────────────────────────────────────────
variable "aws_region" {
  type        = string
  description = "Target AWS deployment region"
  default     = "ap-south-1"
}

variable "environment" {
  type        = string
  description = "Deployment environment name"
  default     = "staging"
}

variable "project_name" {
  type        = string
  description = "Project name prefix for resource naming and tagging"
  default     = "bsea"
}

# ── Networking (VPC) ─────────────────────────────────────────────────────────
variable "vpc_cidr" {
  type        = string
  description = "Base CIDR block for the dedicated B-SEA VPC"
  default     = "10.0.0.0/16"
}

# ── Database (RDS PostgreSQL 16) ─────────────────────────────────────────────
variable "db_name" {
  type        = string
  description = "Authoritative PostgreSQL database name"
  default     = "bsea"
}

variable "db_username" {
  type        = string
  description = "PostgreSQL master username"
  default     = "bsea_admin"
}

variable "db_instance_class" {
  type        = string
  description = "Instance type for RDS PostgreSQL (default: db.t4g.medium for verified RDS Proxy compatibility)"
  default     = "db.t4g.medium"
}

variable "db_allocated_storage" {
  type        = number
  description = "Allocated storage in GB for RDS PostgreSQL (gp3)"
  default     = 20
}

# ── Cache (ElastiCache Redis 7) ──────────────────────────────────────────────
variable "redis_node_type" {
  type        = string
  description = "ElastiCache Redis node type for staging"
  default     = "cache.t4g.micro"
}

# ── Compute (ECS Fargate) ────────────────────────────────────────────────────
variable "backend_container_image" {
  type        = string
  description = "Container image URI for B-SEA backend (e.g. from ECR)"
  default     = "123456789012.dkr.ecr.ap-south-1.amazonaws.com/bsea-backend-staging:latest"
}

variable "task_cpu" {
  type        = number
  description = "CPU units allocated to backend Fargate task (512 = 0.5 vCPU)"
  default     = 512
}

variable "task_memory" {
  type        = number
  description = "Memory in MB allocated to backend Fargate task (1024 = 1 GB)"
  default     = 1024
}

variable "desired_task_count" {
  type        = number
  description = "Desired number of running backend tasks in the ECS service"
  default     = 2
}

variable "min_task_count" {
  type        = number
  description = "Minimum number of tasks for ECS service autoscaling"
  default     = 2
}

variable "max_task_count" {
  type        = number
  description = "Maximum number of tasks for ECS service autoscaling"
  default     = 4
}

# ── Ingress (ALB & ACM) ──────────────────────────────────────────────────────
variable "acm_certificate_arn" {
  type        = string
  description = "ARN of an existing ACM certificate for ALB HTTPS listener (optional for dry runs)"
  default     = ""
}

variable "custom_api_domain" {
  type        = string
  description = "Custom API domain (e.g. api-staging.bsea.gov.in) matching ACM certificate on ALB (Option A). If empty, falls back to ALB DNS name with runtime status CLOUDFRONT_TO_ALB_HTTPS_RUNTIME_VALIDATION_PENDING (Option B)."
  default     = ""
}

# ── Cryptographic Provider (KMS) ─────────────────────────────────────────────
variable "kms_provider" {
  type        = string
  description = "Cryptographic provider for backend workloads ('aws' for cloud staging/production, 'mock' for local development)"
  default     = "aws"
}
