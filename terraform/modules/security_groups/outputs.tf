output "alb_sg_id" {
  value       = aws_security_group.alb.id
  description = "Security Group ID of the Application Load Balancer"
}

output "ecs_sg_id" {
  value       = aws_security_group.ecs.id
  description = "Security Group ID of the ECS Fargate backend tasks"
}

output "rds_proxy_sg_id" {
  value       = aws_security_group.rds_proxy.id
  description = "Security Group ID of the AWS RDS Proxy"
}

output "rds_sg_id" {
  value       = aws_security_group.rds.id
  description = "Security Group ID of the RDS PostgreSQL instance"
}

output "redis_sg_id" {
  value       = aws_security_group.redis.id
  description = "Security Group ID of the ElastiCache Redis cluster"
}
