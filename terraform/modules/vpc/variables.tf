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

variable "vpc_cidr" {
  type        = string
  description = "Base CIDR block for the dedicated B-SEA VPC"
  default     = "10.0.0.0/16"
}
