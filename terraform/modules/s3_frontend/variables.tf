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

variable "alb_dns_name" {
  type        = string
  description = "DNS hostname of the Application Load Balancer"
}

variable "custom_api_domain" {
  type        = string
  description = "Custom API domain (e.g. api-staging.domain.com) matching ACM cert on ALB to prevent SSL origin mismatch (Option A). If empty, falls back to alb_dns_name with CLOUDFRONT_TO_ALB_HTTPS_RUNTIME_VALIDATION_PENDING (Option B)."
  default     = ""
}

variable "force_destroy" {
  type        = bool
  description = "Enable force destroy on S3 bucket (staging teardown-friendly)"
  default     = true
}
