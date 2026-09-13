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

variable "force_delete" {
  type        = bool
  description = "Whether to delete repository even if it contains images (staging teardown-friendly)"
  default     = true
}
