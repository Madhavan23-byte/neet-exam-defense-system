output "db_secret_arn" {
  value       = aws_secretsmanager_secret.db_credentials.arn
  description = "ARN of the Secrets Manager database credentials secret"
}

output "db_secret_name" {
  value       = aws_secretsmanager_secret.db_credentials.name
  description = "Name of the Secrets Manager database credentials secret"
}

output "redis_secret_arn" {
  value       = aws_secretsmanager_secret.redis_auth.arn
  description = "ARN of the Secrets Manager Redis AUTH token secret"
}

output "jwt_secret_arn" {
  value       = aws_secretsmanager_secret.jwt_secret.arn
  description = "ARN of the Secrets Manager application JWT secret"
}

# Values for internal module parameter feeding (e.g. RDS and ElastiCache provisioners)
output "db_master_password" {
  value       = random_password.db_master.result
  sensitive   = true
  description = "Generated master database password (sensitive, for RDS module binding)"
}

output "redis_auth_token" {
  value       = random_password.redis_auth.result
  sensitive   = true
  description = "Generated Redis auth token (sensitive, for ElastiCache module binding)"
}
