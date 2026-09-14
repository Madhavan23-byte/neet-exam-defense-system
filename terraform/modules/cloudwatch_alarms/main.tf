# ── B-SEA Observability Foundation (Phase 3C-5B) ──────────────────────────────
# Reusable CloudWatch Alarms & Metric Filters with Single Authoritative Metric Sources

# ── SNS Alerts Topic (Encrypted with AWS KMS) ──────────────────────────────────
resource "aws_sns_topic" "alerts" {
  name              = "${var.project_name}-${var.environment}-alerts"
  kms_master_key_id = var.kms_key_arn != null ? var.kms_key_arn : "alias/aws/sns"

  tags = {
    Name        = "${var.project_name}-${var.environment}-alerts"
    Project     = var.project_name
    Environment = var.environment
    Component   = "Observability"
  }
}

# Conceptual placeholder for human operator notification destination
resource "aws_sns_topic_subscription" "email_placeholder" {
  count     = var.enable_email_notifications ? 1 : 0
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.notification_email
}

# ── 1. High 5xx Error Rate (Authoritative Source: ALB Native Metric) ───────────
resource "aws_cloudwatch_metric_alarm" "high_5xx_rate" {
  alarm_name          = "${var.project_name}-${var.environment}-high-5xx-rate"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "HTTPCode_Target_5XX_Count"
  namespace           = "AWS/ApplicationELB"
  period              = 60
  statistic           = "Sum"
  threshold           = 10
  alarm_description   = "Triggered when ALB target 5XX error count exceeds 10 in a 1-minute window."
  alarm_actions       = [aws_sns_topic.alerts.arn]
  treat_missing_data  = "notBreaching"

  dimensions = {
    LoadBalancer = var.alb_arn_suffix
  }
}

# ── 2. High P95 Latency (Authoritative Source: ALB Native Metric) ───────────────
resource "aws_cloudwatch_metric_alarm" "high_p95_latency" {
  alarm_name          = "${var.project_name}-${var.environment}-high-p95-latency"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "TargetResponseTime"
  namespace           = "AWS/ApplicationELB"
  period              = 60
  extended_statistic  = "p95"
  threshold           = 1.5
  alarm_description   = "Triggered when P95 response time exceeds 1.5s for 2 consecutive 1-minute periods."
  alarm_actions       = [aws_sns_topic.alerts.arn]
  treat_missing_data  = "notBreaching"

  dimensions = {
    LoadBalancer = var.alb_arn_suffix
    TargetGroup  = var.target_group_arn_suffix
  }
}

# ── 3. Unhealthy ECS Tasks (Authoritative Source: ALB Native Metric) ───────────
resource "aws_cloudwatch_metric_alarm" "unhealthy_ecs_tasks" {
  alarm_name          = "${var.project_name}-${var.environment}-unhealthy-ecs-tasks"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = "UnHealthyHostCount"
  namespace           = "AWS/ApplicationELB"
  period              = 60
  statistic           = "Maximum"
  threshold           = 1
  alarm_description   = "Triggered when at least 1 ECS task target becomes unhealthy in ALB target group."
  alarm_actions       = [aws_sns_topic.alerts.arn]
  treat_missing_data  = "breaching"

  dimensions = {
    LoadBalancer = var.alb_arn_suffix
    TargetGroup  = var.target_group_arn_suffix
  }
}

# ── 4. Excessive Auth Failures (Authoritative Source: CloudWatch Log Metric Filter)
resource "aws_cloudwatch_log_metric_filter" "auth_failures" {
  name           = "${var.project_name}-${var.environment}-auth-failures-filter"
  log_group_name = var.log_group_name
  pattern        = "{ ($.logger = \"bsea.telemetry\") && ($.error_code = \"AUTH_FAILED\") }"

  metric_transformation {
    name          = "AuthFailuresCount"
    namespace     = "${var.project_name}/${var.environment}/Security"
    value         = "1"
    default_value = 0
  }
}

resource "aws_cloudwatch_metric_alarm" "excessive_auth_failures" {
  alarm_name          = "${var.project_name}-${var.environment}-excessive-auth-failures"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = "AuthFailuresCount"
  namespace           = "${var.project_name}/${var.environment}/Security"
  period              = 60
  statistic           = "Sum"
  threshold           = 5
  alarm_description   = "Triggered when authentication failures reach 5 or more within 1 minute."
  alarm_actions       = [aws_sns_topic.alerts.arn]
  treat_missing_data  = "notBreaching"
}

# ── 5. Authorization Denials Spike (Authoritative Source: CloudWatch Log Metric Filter)
resource "aws_cloudwatch_log_metric_filter" "authz_denials" {
  name           = "${var.project_name}-${var.environment}-authz-denials-filter"
  log_group_name = var.log_group_name
  pattern        = "{ ($.logger = \"bsea.telemetry\") && ($.error_code = \"FORBIDDEN\") }"

  metric_transformation {
    name          = "AuthzDenialsCount"
    namespace     = "${var.project_name}/${var.environment}/Security"
    value         = "1"
    default_value = 0
  }
}

resource "aws_cloudwatch_metric_alarm" "excessive_authz_denials" {
  alarm_name          = "${var.project_name}-${var.environment}-excessive-authz-denials"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = "AuthzDenialsCount"
  namespace           = "${var.project_name}/${var.environment}/Security"
  period              = 60
  statistic           = "Sum"
  threshold           = 10
  alarm_description   = "Triggered when authorization denials reach 10 or more within 1 minute."
  alarm_actions       = [aws_sns_topic.alerts.arn]
  treat_missing_data  = "notBreaching"
}

# ── 6. Rate Limit Spike (Authoritative Source: CloudWatch Log Metric Filter) ────
resource "aws_cloudwatch_log_metric_filter" "rate_limits" {
  name           = "${var.project_name}-${var.environment}-rate-limits-filter"
  log_group_name = var.log_group_name
  pattern        = "{ ($.logger = \"bsea.telemetry\") && ($.error_code = \"RATE_LIMITED\") }"

  metric_transformation {
    name          = "RateLimitRejectionsCount"
    namespace     = "${var.project_name}/${var.environment}/Security"
    value         = "1"
    default_value = 0
  }
}

resource "aws_cloudwatch_metric_alarm" "excessive_rate_limits" {
  alarm_name          = "${var.project_name}-${var.environment}-excessive-rate-limits"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = "RateLimitRejectionsCount"
  namespace           = "${var.project_name}/${var.environment}/Security"
  period              = 60
  statistic           = "Sum"
  threshold           = 20
  alarm_description   = "Triggered when rate limit rejections reach 20 or more within 1 minute."
  alarm_actions       = [aws_sns_topic.alerts.arn]
  treat_missing_data  = "notBreaching"
}

# ── 7. Question Grant Denial Spike (Authoritative Source: CloudWatch Log Metric Filter)
resource "aws_cloudwatch_log_metric_filter" "question_grant_denials" {
  name           = "${var.project_name}-${var.environment}-question-grant-denials-filter"
  log_group_name = var.log_group_name
  pattern        = "{ ($.logger = \"bsea.telemetry\") && ($.event_type = \"EXAM_QUESTION_DECRYPT\") && ($.result = \"DENIED\") }"

  metric_transformation {
    name          = "QuestionGrantDenialsCount"
    namespace     = "${var.project_name}/${var.environment}/Security"
    value         = "1"
    default_value = 0
  }
}

resource "aws_cloudwatch_metric_alarm" "question_grant_denials_spike" {
  alarm_name          = "${var.project_name}-${var.environment}-question-grant-denials-spike"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = "QuestionGrantDenialsCount"
  namespace           = "${var.project_name}/${var.environment}/Security"
  period              = 60
  statistic           = "Sum"
  threshold           = 3
  alarm_description   = "Triggered when unauthorized question paper decryption attempts reach 3 within 1 minute."
  alarm_actions       = [aws_sns_topic.alerts.arn]
  treat_missing_data  = "notBreaching"
}

# ── 8. Break Glass Activation Event (Authoritative Source: CloudWatch Log Metric Filter)
resource "aws_cloudwatch_log_metric_filter" "break_glass" {
  name           = "${var.project_name}-${var.environment}-break-glass-filter"
  log_group_name = var.log_group_name
  pattern        = "{ ($.logger = \"bsea.telemetry\") && ($.event_type = \"BREAK_GLASS_*\") }"

  metric_transformation {
    name          = "BreakGlassEventsCount"
    namespace     = "${var.project_name}/${var.environment}/Security"
    value         = "1"
    default_value = 0
  }
}

resource "aws_cloudwatch_metric_alarm" "break_glass_event" {
  alarm_name          = "${var.project_name}-${var.environment}-break-glass-event"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = "BreakGlassEventsCount"
  namespace           = "${var.project_name}/${var.environment}/Security"
  period              = 60
  statistic           = "Sum"
  threshold           = 1
  alarm_description   = "Critical: Triggered immediately when any break-glass emergency activation occurs."
  alarm_actions       = [aws_sns_topic.alerts.arn]
  treat_missing_data  = "notBreaching"
}

# ── 9. Audit Sealer Error (Authoritative Source: CloudWatch Log Metric Filter) ──
resource "aws_cloudwatch_log_metric_filter" "sealer_errors" {
  name           = "${var.project_name}-${var.environment}-sealer-errors-filter"
  log_group_name = var.log_group_name
  pattern        = "{ ($.logger = \"bsea.audit.sealer\") && ($.level = \"ERROR\") }"

  metric_transformation {
    name          = "AuditSealerErrorsCount"
    namespace     = "${var.project_name}/${var.environment}/Security"
    value         = "1"
    default_value = 0
  }
}

resource "aws_cloudwatch_metric_alarm" "audit_sealer_failure" {
  alarm_name          = "${var.project_name}-${var.environment}-audit-sealer-failure"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = "AuditSealerErrorsCount"
  namespace           = "${var.project_name}/${var.environment}/Security"
  period              = 300
  statistic           = "Sum"
  threshold           = 1
  alarm_description   = "Triggered when an unhandled error occurs during audit epoch sealing."
  alarm_actions       = [aws_sns_topic.alerts.arn]
  treat_missing_data  = "notBreaching"
}

# ── 10. Deep Verifier Failure (Authoritative Source: CloudWatch Log Metric Filter)
resource "aws_cloudwatch_log_metric_filter" "verifier_failures" {
  name           = "${var.project_name}-${var.environment}-verifier-failures-filter"
  log_group_name = var.log_group_name
  pattern        = "{ ($.logger = \"bsea.audit.service\") && ($.level = \"ERROR\") && ($.message = \"*Deep Verifier Failed*\") }"

  metric_transformation {
    name          = "AuditVerifierFailuresCount"
    namespace     = "${var.project_name}/${var.environment}/Security"
    value         = "1"
    default_value = 0
  }
}

resource "aws_cloudwatch_metric_alarm" "audit_verifier_failure" {
  alarm_name          = "${var.project_name}-${var.environment}-audit-verifier-failure"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = "AuditVerifierFailuresCount"
  namespace           = "${var.project_name}/${var.environment}/Security"
  period              = 60
  statistic           = "Sum"
  threshold           = 1
  alarm_description   = "Critical: Triggered when cryptographic audit verifier detects chain corruption, gap, or hash mismatch."
  alarm_actions       = [aws_sns_topic.alerts.arn]
  treat_missing_data  = "notBreaching"
}
