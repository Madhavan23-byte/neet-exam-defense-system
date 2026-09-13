output "db_instance_id" {
  value       = aws_db_instance.postgres.id
  description = "The RDS PostgreSQL instance identifier"
}

output "db_instance_endpoint" {
  value       = aws_db_instance.postgres.endpoint
  description = "The connection endpoint for the RDS instance"
}

output "db_instance_address" {
  value       = aws_db_instance.postgres.address
  description = "The hostname address of the RDS instance"
}

output "db_instance_port" {
  value       = aws_db_instance.postgres.port
  description = "The database port (5432)"
}

output "db_name" {
  value       = aws_db_instance.postgres.db_name
  description = "The default database name"
}
