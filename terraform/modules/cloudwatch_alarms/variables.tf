variable "project_name" {
  description = "Project prefix for resource names"
  type        = string
  default     = "bsea"
}

variable "environment" {
  description = "Deployment environment (e.g. staging, production)"
  type        = string
  default     = "staging"
}

variable "alb_arn_suffix" {
  description = "ARN suffix of the Application Load Balancer for CloudWatch metrics"
  type        = string
  default     = ""
}

variable "target_group_arn_suffix" {
  description = "ARN suffix of the target group for CloudWatch metrics"
  type        = string
  default     = ""
}

variable "log_group_name" {
  description = "CloudWatch log group name where structured JSON application logs are emitted"
  type        = string
  default     = "/ecs/bsea-staging-backend"
}

variable "kms_key_arn" {
  description = "KMS Key ARN for server-side encryption of SNS topics"
  type        = string
  default     = null
}

variable "enable_email_notifications" {
  description = "Conceptual placeholder toggle for SNS email subscription"
  type        = bool
  default     = false
}

variable "notification_email" {
  description = "Conceptual placeholder email recipient for alerts"
  type        = string
  default     = "security-alerts@example.com"
}
