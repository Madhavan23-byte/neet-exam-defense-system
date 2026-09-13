output "repository_url" {
  value       = aws_ecr_repository.backend.repository_url
  description = "The URL of the B-SEA backend ECR repository"
}

output "repository_arn" {
  value       = aws_ecr_repository.backend.arn
  description = "The ARN of the B-SEA backend ECR repository"
}

output "repository_name" {
  value       = aws_ecr_repository.backend.name
  description = "The name of the B-SEA backend ECR repository"
}
