terraform {
  required_version = ">= 1.5.0, < 2.0.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.80, < 7.0.0"
    }
  }
}

# ── Application Load Balancer ────────────────────────────────────────────────
resource "aws_lb" "alb" {
  name               = "${var.project_name}-alb-${var.environment}"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [var.alb_sg_id]
  subnets            = var.public_subnet_ids

  drop_invalid_header_fields = true
  enable_deletion_protection = var.enable_deletion_protection # Staging teardown-friendly

  tags = {
    Name = "${var.project_name}-alb-${var.environment}"
  }
}

# ── Target Group for ECS Fargate Tasks ───────────────────────────────────────
resource "aws_lb_target_group" "ecs" {
  name        = "${var.project_name}-tg-${var.environment}"
  port        = 8000
  protocol    = "HTTP"
  vpc_id      = var.vpc_id
  target_type = "ip"

  # CRITICAL ARCHITECTURAL REQUIREMENT:
  # Use /health/live for ALB target group liveness.
  # Do NOT use /health/ready here (which would drop entire service on transient DB/Redis hiccups).
  health_check {
    path                = "/health/live"
    protocol            = "HTTP"
    port                = "8000"
    matcher             = "200"
    healthy_threshold   = 2
    unhealthy_threshold = 5
    timeout             = 5
    interval            = 15
  }

  tags = {
    Name = "${var.project_name}-tg-${var.environment}"
  }
}

# ── ALB Listeners ────────────────────────────────────────────────────────────

# HTTPS Listener (Port 443) when ACM certificate is supplied
resource "aws_lb_listener" "https" {
  count             = var.acm_certificate_arn != "" ? 1 : 0
  load_balancer_arn = aws_lb.alb.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"
  certificate_arn   = var.acm_certificate_arn

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.ecs.arn
  }
}

# HTTP Listener (Port 80): Redirects to HTTPS when certificate exists; forwards directly in local test sandboxes
resource "aws_lb_listener" "http" {
  load_balancer_arn = aws_lb.alb.arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type = var.acm_certificate_arn != "" ? "redirect" : "forward"

    dynamic "redirect" {
      for_each = var.acm_certificate_arn != "" ? [1] : []
      content {
        port        = "443"
        protocol    = "HTTPS"
        status_code = "HTTP_301"
      }
    }

    target_group_arn = var.acm_certificate_arn == "" ? aws_lb_target_group.ecs.arn : null
  }
}

# ── Regional AWS WAFv2 Web ACL ───────────────────────────────────────────────
resource "aws_wafv2_web_acl" "alb" {
  name        = "${var.project_name}-waf-${var.environment}"
  description = "Regional WAF perimeter protection for B-SEA Application Load Balancer"
  scope       = "REGIONAL"

  default_action {
    allow {}
  }

  # Rule 1: AWS Managed Core Rule Set
  rule {
    name     = "AWSManagedRulesCommonRuleSet"
    priority = 10

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesCommonRuleSet"
        vendor_name = "AWS"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "CommonRuleSetMetric"
      sampled_requests_enabled   = true
    }
  }

  # Rule 2: AWS Managed Known Bad Inputs Rule Set
  rule {
    name     = "AWSManagedRulesKnownBadInputsRuleSet"
    priority = 20

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesKnownBadInputsRuleSet"
        vendor_name = "AWS"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "KnownBadInputsMetric"
      sampled_requests_enabled   = true
    }
  }

  # Rule 3: IP Rate Limiting (Perimeter defense: 2000 requests per 5 minutes per IP)
  # NOTE: WAF edge rate limiting complements, but DOES NOT replace, internal slowapi differentiated rate limiting.
  rule {
    name     = "PerimeterIPRateLimit"
    priority = 30

    action {
      block {}
    }

    statement {
      rate_based_statement {
        limit              = 2000
        aggregate_key_type = "IP"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "PerimeterRateLimitMetric"
      sampled_requests_enabled   = true
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "${var.project_name}-waf-${var.environment}-metrics"
    sampled_requests_enabled   = true
  }

  tags = {
    Name = "${var.project_name}-waf-${var.environment}"
  }
}

# Associate WAF Web ACL with ALB
resource "aws_wafv2_web_acl_association" "alb" {
  resource_arn = aws_lb.alb.arn
  web_acl_arn  = aws_wafv2_web_acl.alb.arn
}
