output "cluster_id" {
  value       = aws_ecs_cluster.cluster.id
  description = "The ID of the ECS cluster"
}

output "cluster_name" {
  value       = aws_ecs_cluster.cluster.name
  description = "The name of the ECS cluster"
}

output "service_name" {
  value       = aws_ecs_service.backend.name
  description = "The name of the ECS backend service"
}

output "task_definition_arn" {
  value       = aws_ecs_task_definition.backend.arn
  description = "The ARN of the ECS task definition"
}

output "log_group_name" {
  value       = aws_cloudwatch_log_group.ecs.name
  description = "The CloudWatch log group name for the backend service"
}
