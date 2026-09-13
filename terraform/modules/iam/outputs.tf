output "ecs_execution_role_arn" {
  value       = aws_iam_role.ecs_execution.arn
  description = "ARN of the ECS Fargate Task Execution Role"
}

output "ecs_task_role_arn" {
  value       = aws_iam_role.ecs_task.arn
  description = "ARN of the ECS Fargate Task Role"
}

output "rds_proxy_role_arn" {
  value       = aws_iam_role.rds_proxy.arn
  description = "ARN of the IAM role assumed by RDS Proxy"
}
