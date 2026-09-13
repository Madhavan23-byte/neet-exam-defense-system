output "proxy_id" {
  value       = aws_db_proxy.proxy.id
  description = "The ID of the RDS Proxy"
}

output "proxy_arn" {
  value       = aws_db_proxy.proxy.arn
  description = "The ARN of the RDS Proxy"
}

output "proxy_endpoint" {
  value       = aws_db_proxy.proxy.endpoint
  description = "The connection endpoint hostname of the RDS Proxy"
}
