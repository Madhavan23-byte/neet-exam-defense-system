output "vpc_id" {
  value       = module.vpc.vpc_id
  description = "The ID of the provisioned B-SEA VPC"
}

output "availability_zones" {
  value       = module.vpc.availability_zones
  description = "The dynamically selected Availability Zones"
}

output "alb_dns_name" {
  value       = module.alb.alb_dns_name
  description = "The public DNS name of the Application Load Balancer"
}

output "cloudfront_domain_name" {
  value       = module.s3_frontend.cloudfront_domain_name
  description = "The CloudFront edge distribution domain name"
}

output "s3_frontend_bucket" {
  value       = module.s3_frontend.s3_bucket_name
  description = "The S3 bucket name hosting the React frontend assets"
}

output "ecr_repository_url" {
  value       = module.ecr.repository_url
  description = "The private ECR repository URL for backend container images"
}

output "ecs_cluster_name" {
  value       = module.ecs.cluster_name
  description = "The name of the ECS cluster"
}

output "ecs_service_name" {
  value       = module.ecs.service_name
  description = "The name of the ECS backend service"
}

output "rds_proxy_endpoint" {
  value       = module.rds_proxy.proxy_endpoint
  description = "The connection endpoint for the AWS RDS Proxy (used by backend tasks)"
}

# ── KMS Cryptographic Outputs ─────────────────────────────────────────────────
output "kms_symmetric_key_arn" {
  value       = module.kms.symmetric_key_arn
  description = "ARN of the AWS KMS symmetric key used for AES-256 envelope encryption"
}

output "kms_symmetric_alias" {
  value       = module.kms.symmetric_alias_arn
  description = "ARN of the alias for the AWS KMS symmetric encryption key"
}

output "kms_signing_key_arn" {
  value       = module.kms.asymmetric_signing_key_arn
  description = "ARN of the AWS KMS asymmetric Ed25519 key used for digital signing"
}

output "kms_signing_alias" {
  value       = module.kms.asymmetric_signing_alias_arn
  description = "ARN of the alias for the AWS KMS asymmetric Ed25519 signing key"
}
