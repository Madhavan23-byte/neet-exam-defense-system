output "alb_id" {
  value       = aws_lb.alb.id
  description = "The ID of the Application Load Balancer"
}

output "alb_arn" {
  value       = aws_lb.alb.arn
  description = "The ARN of the Application Load Balancer"
}

output "alb_dns_name" {
  value       = aws_lb.alb.dns_name
  description = "The public DNS name of the Application Load Balancer"
}

output "target_group_arn" {
  value       = aws_lb_target_group.ecs.arn
  description = "The ARN of the target group pointing to ECS backend tasks"
}

output "waf_web_acl_arn" {
  value       = aws_wafv2_web_acl.alb.arn
  description = "The ARN of the regional WAF Web ACL attached to the ALB"
}
