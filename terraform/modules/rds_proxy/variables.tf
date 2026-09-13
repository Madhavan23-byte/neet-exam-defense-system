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

variable "database_subnet_ids" {
  type        = list(string)
  description = "List of isolated database subnet IDs where the proxy will be attached"
}

variable "rds_proxy_sg_id" {
  type        = string
  description = "Security group ID for RDS Proxy (allows ingress from ECS, egress to RDS)"
}

variable "rds_proxy_role_arn" {
  type        = string
  description = "IAM role ARN assumed by RDS Proxy to access Secrets Manager"
}

variable "db_secret_arn" {
  type        = string
  description = "Secrets Manager secret ARN containing database credentials"
}

variable "db_instance_id" {
  type        = string
  description = "Database instance identifier of the target RDS PostgreSQL database"
}
