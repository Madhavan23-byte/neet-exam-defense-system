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

variable "db_username" {
  type        = string
  description = "Master username for PostgreSQL database"
  default     = "bsea_admin"
}

variable "db_name" {
  type        = string
  description = "Name of the default PostgreSQL database"
  default     = "bsea"
}

variable "recovery_window_in_days" {
  type        = number
  description = "Secrets Manager recovery window in days (0 for immediate disposal in staging)"
  default     = 0
}
