output "sns_topic_arn" {
  description = "ARN of the SNS topic for B-SEA observability alerts"
  value       = aws_sns_topic.alerts.arn
}

output "sns_topic_name" {
  description = "Name of the SNS topic for B-SEA observability alerts"
  value       = aws_sns_topic.alerts.name
}

output "alarm_arns" {
  description = "Map of CloudWatch alarm names to their ARNs"
  value = {
    high_5xx_rate                = aws_cloudwatch_metric_alarm.high_5xx_rate.arn
    high_p95_latency             = aws_cloudwatch_metric_alarm.high_p95_latency.arn
    unhealthy_ecs_tasks          = aws_cloudwatch_metric_alarm.unhealthy_ecs_tasks.arn
    excessive_auth_failures      = aws_cloudwatch_metric_alarm.excessive_auth_failures.arn
    excessive_authz_denials      = aws_cloudwatch_metric_alarm.excessive_authz_denials.arn
    excessive_rate_limits        = aws_cloudwatch_metric_alarm.excessive_rate_limits.arn
    question_grant_denials_spike = aws_cloudwatch_metric_alarm.question_grant_denials_spike.arn
    break_glass_event            = aws_cloudwatch_metric_alarm.break_glass_event.arn
    audit_sealer_failure         = aws_cloudwatch_metric_alarm.audit_sealer_failure.arn
    audit_verifier_failure       = aws_cloudwatch_metric_alarm.audit_verifier_failure.arn
  }
}
