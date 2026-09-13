output "vpc_id" {
  value       = aws_vpc.main.id
  description = "The ID of the dedicated B-SEA VPC"
}

output "public_subnet_ids" {
  value       = aws_subnet.public[*].id
  description = "IDs of the public subnets (ALB & NAT only)"
}

output "private_app_subnet_ids" {
  value       = aws_subnet.private_app[*].id
  description = "IDs of the private application subnets (ECS Fargate only)"
}

output "database_subnet_ids" {
  value       = aws_subnet.database[*].id
  description = "IDs of the isolated database subnets (RDS, RDS Proxy, ElastiCache only)"
}

output "availability_zones" {
  value       = local.selected_azs
  description = "Dynamically selected Availability Zones utilized for deployment"
}
