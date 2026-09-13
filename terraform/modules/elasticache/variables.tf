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
  description = "List of isolated database subnet IDs where Redis will be hosted"
}

variable "redis_sg_id" {
  type        = string
  description = "Security group ID for Redis (allows ingress strictly from ECS SG)"
}

variable "redis_node_type" {
  type        = string
  description = "ElastiCache node type for staging"
  default     = "cache.t4g.micro"
}

variable "redis_auth_token" {
  type        = string
  description = "AUTH token for Redis client authentication (sensitive)"
  sensitive   = true
}
