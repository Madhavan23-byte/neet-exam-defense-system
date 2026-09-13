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

variable "vpc_id" {
  type        = string
  description = "VPC ID where ALB and target groups are provisioned"
}

variable "public_subnet_ids" {
  type        = list(string)
  description = "List of public subnet IDs for the internet-facing ALB"
}

variable "alb_sg_id" {
  type        = string
  description = "Security group ID for the ALB"
}

variable "acm_certificate_arn" {
  type        = string
  description = "ARN of the ACM certificate for HTTPS listener (optional for local dry-run sandboxes)"
  default     = ""
}

variable "enable_deletion_protection" {
  type        = bool
  description = "Enable ALB deletion protection (false for staging teardown)"
  default     = false
}
