output "replication_group_id" {
  value       = aws_elasticache_replication_group.redis.id
  description = "The ID of the ElastiCache replication group"
}

output "primary_endpoint_address" {
  value       = aws_elasticache_replication_group.redis.primary_endpoint_address
  description = "The primary endpoint hostname of the Redis cluster"
}

output "port" {
  value       = aws_elasticache_replication_group.redis.port
  description = "The Redis connection port (6379)"
}
