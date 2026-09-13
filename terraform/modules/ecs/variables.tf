variable "project_name" {
  type        = string
  description = "Project name prefix for resource naming and tagging"
  default     = "bsea"
}

variable "environment" {
  type        = string
  description = "Deployment environment name (e.g. staging, production)"
  default     = "staging"
}

variable "aws_region" {
  type        = string
  description = "AWS deployment region (e.g. ap-south-1)"
  default     = "ap-south-1"
}

variable "private_app_subnet_ids" {
  type        = list(string)
  description = "List of private application subnets where Fargate tasks will run"
}

variable "ecs_sg_id" {
  type        = string
  description = "Security group ID for ECS Fargate tasks"
}

variable "target_group_arn" {
  type        = string
  description = "Target group ARN to attach the ECS service to"
}

variable "ecs_execution_role_arn" {
  type        = string
  description = "Execution role ARN for the ECS tasks"
}

variable "ecs_task_role_arn" {
  type        = string
  description = "Task role ARN for the ECS tasks"
}

variable "backend_container_image" {
  type        = string
  description = "ECR image URI for the backend container"
}

variable "task_cpu" {
  type        = number
  description = "Fargate task CPU units (512 = 0.5 vCPU)"
  default     = 512
}

variable "task_memory" {
  type        = number
  description = "Fargate task memory in MB (1024 = 1 GB)"
  default     = 1024
}

variable "desired_count" {
  type        = number
  description = "Initial desired task count for the ECS service"
  default     = 2
}

variable "min_count" {
  type        = number
  description = "Minimum task count for autoscaling"
  default     = 2
}

variable "max_count" {
  type        = number
  description = "Maximum task count for autoscaling"
  default     = 4
}

variable "log_retention_days" {
  type        = number
  description = "CloudWatch log retention in days for staging"
  default     = 30
}

variable "rds_proxy_endpoint" {
  type        = string
  description = "Hostname endpoint of the RDS Proxy"
}

variable "db_name" {
  type        = string
  description = "Name of the target PostgreSQL database"
  default     = "bsea"
}

variable "db_username" {
  type        = string
  description = "Database master username"
  default     = "bsea_admin"
}

variable "redis_endpoint" {
  type        = string
  description = "Primary endpoint hostname of the ElastiCache Redis cluster"
}

variable "redis_port" {
  type        = number
  description = "Port of the ElastiCache Redis cluster"
  default     = 6379
}

variable "db_secret_arn" {
  type        = string
  description = "Secrets Manager secret ARN for database credentials"
}

variable "redis_secret_arn" {
  type        = string
  description = "Secrets Manager secret ARN for Redis AUTH token"
}

variable "jwt_secret_arn" {
  type        = string
  description = "Secrets Manager secret ARN for JWT secret key"
}
