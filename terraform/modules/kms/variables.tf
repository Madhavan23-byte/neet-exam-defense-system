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

variable "ecs_task_role_arn" {
  type        = string
  description = "ARN of the ECS task IAM role allowed to use the KMS keys for runtime crypto"
}
