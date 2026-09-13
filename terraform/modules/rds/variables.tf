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
  description = "List of isolated database subnet IDs"
}

variable "rds_sg_id" {
  type        = string
  description = "Security group ID for RDS PostgreSQL (allows ingress strictly from RDS Proxy)"
}

variable "db_name" {
  type        = string
  description = "PostgreSQL default database name"
  default     = "bsea"
}

variable "db_username" {
  type        = string
  description = "PostgreSQL master username"
  default     = "bsea_admin"
}

variable "db_password" {
  type        = string
  description = "PostgreSQL master password (sensitive)"
  sensitive   = true
}

variable "db_instance_class" {
  type        = string
  description = "RDS instance class (default: db.t4g.medium for verified RDS Proxy compatibility)"
  default     = "db.t4g.medium"
}

variable "db_allocated_storage" {
  type        = number
  description = "Allocated storage in GB for gp3 volume"
  default     = 20
}

variable "engine_version" {
  type        = string
  description = "PostgreSQL major/minor engine version"
  default     = "16.4"
}

variable "skip_final_snapshot" {
  type        = bool
  description = "Skip final snapshot on deletion (staging teardown only)"
  default     = true
}

variable "deletion_protection" {
  type        = bool
  description = "Enable database deletion protection"
  default     = false
}
