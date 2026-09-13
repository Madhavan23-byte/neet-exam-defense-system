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

variable "db_secret_arn" {
  type        = string
  description = "ARN of the Secrets Manager secret for database credentials"
}

variable "redis_secret_arn" {
  type        = string
  description = "ARN of the Secrets Manager secret for Redis AUTH token"
}

variable "jwt_secret_arn" {
  type        = string
  description = "ARN of the Secrets Manager secret for JWT secret key"
}

variable "kms_encryption_key_arn" {
  type        = string
  description = "ARN of the AWS KMS symmetric key for envelope encryption"
}

variable "kms_signing_key_arn" {
  type        = string
  description = "ARN of the AWS KMS asymmetric Ed25519 key for signing"
}
