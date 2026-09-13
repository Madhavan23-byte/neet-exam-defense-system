terraform {
  required_version = ">= 1.5.0, < 2.0.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.80, < 7.0.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.6"
    }
  }
}

# Unique suffix for S3 bucket name
resource "random_string" "bucket_suffix" {
  length  = 8
  special = false
  upper   = false
}

# ── 1. Private S3 Bucket for React Static Assets ─────────────────────────────
resource "aws_s3_bucket" "frontend" {
  bucket        = "${var.project_name}-frontend-${var.environment}-${random_string.bucket_suffix.result}"
  force_destroy = var.force_destroy # Staging teardown-friendly

  tags = {
    Name = "${var.project_name}-frontend-${var.environment}"
  }
}

# Strict Block Public Access (Zero Public Bucket Access)
resource "aws_s3_bucket_public_access_block" "frontend" {
  bucket = aws_s3_bucket.frontend.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Standard Server-Side Encryption (AWS-Managed AES256)
resource "aws_s3_bucket_server_side_encryption_configuration" "frontend" {
  bucket = aws_s3_bucket.frontend.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# ── 2. CloudFront Origin Access Control (OAC) ────────────────────────────────
resource "aws_cloudfront_origin_access_control" "frontend" {
  name                              = "${var.project_name}-oac-${var.environment}"
  description                       = "OAC for B-SEA React frontend S3 origin"
  origin_access_control_origin_type = "s3"
  signing_behavior                  = "always"
  signing_protocol                  = "sigv4"
}

locals {
  # OPTION A (Preferred): When custom_api_domain is supplied (matching the ACM certificate on the ALB),
  # CloudFront routes HTTPS directly to custom_api_domain, ensuring valid TLS SNI hostname matching.
  # OPTION B: If custom_api_domain is omitted, falls back to alb_dns_name with runtime status:
  # CLOUDFRONT_TO_ALB_HTTPS_RUNTIME_VALIDATION_PENDING (requires ACM cert matching ALB domain before deployment).
  api_origin_domain = var.custom_api_domain != "" ? var.custom_api_domain : var.alb_dns_name
}

# ── 3. CloudFront Distribution (Dual Origins: S3 + ALB) ──────────────────────
resource "aws_cloudfront_distribution" "distribution" {
  enabled             = true
  is_ipv6_enabled     = true
  default_root_object = "index.html"
  comment             = "B-SEA CloudFront Distribution for Frontend & API"
  price_class         = "PriceClass_100" # Asia / North America / Europe only for staging cost control

  # Origin 1: S3 Static Web Assets
  origin {
    domain_name              = aws_s3_bucket.frontend.bucket_regional_domain_name
    origin_id                = "S3-${aws_s3_bucket.frontend.id}"
    origin_access_control_id = aws_cloudfront_origin_access_control.frontend.id
  }

  # Origin 2: ALB for FastAPI Backend (/api/* and /health/*)
  origin {
    domain_name = local.api_origin_domain
    origin_id   = "ALB-${var.project_name}"

    custom_origin_config {
      http_port                = 80
      https_port               = 443
      origin_protocol_policy   = "https-only" # Mandatory HTTPS upstream
      origin_ssl_protocols     = ["TLSv1.2"]
      origin_read_timeout      = 60
      origin_keepalive_timeout = 5
    }
  }

  # ── Cache Behavior 1: /api/* (Backend API) ─────────────────────────────────
  # CRITICAL SECURITY INVARIANT:
  # Caching is STRICTLY DISABLED for all API endpoints.
  # CloudFront must never cache authentication tokens, candidate questions,
  # autosaves, or break-glass emergency responses.
  ordered_cache_behavior {
    path_pattern     = "/api/*"
    target_origin_id = "ALB-${var.project_name}"

    allowed_methods = ["DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT"]
    cached_methods  = ["GET", "HEAD"]

    # AWS Managed CachingDisabled Policy (ID: 4135ea2d-6df8-44a3-9df3-44ca84e08d47)
    cache_policy_id = "4135ea2d-6df8-44a3-9df3-44ca84e08d47"

    # AWS Managed AllViewerExceptHostHeader Policy (ID: b689b0a8-53d0-40ab-baf2-68738e2966ac)
    origin_request_policy_id = "b689b0a8-53d0-40ab-baf2-68738e2966ac"

    viewer_protocol_policy = "redirect-to-https"
    compress               = true
  }

  # ── Cache Behavior 2: /health/* (Health Probes) ────────────────────────────
  ordered_cache_behavior {
    path_pattern     = "/health/*"
    target_origin_id = "ALB-${var.project_name}"

    allowed_methods = ["GET", "HEAD", "OPTIONS"]
    cached_methods  = ["GET", "HEAD"]

    cache_policy_id          = "4135ea2d-6df8-44a3-9df3-44ca84e08d47"
    origin_request_policy_id = "b689b0a8-53d0-40ab-baf2-68738e2966ac"

    viewer_protocol_policy = "redirect-to-https"
    compress               = true
  }

  # ── Default Cache Behavior: /* (Static React Frontend) ─────────────────────
  default_cache_behavior {
    target_origin_id = "S3-${aws_s3_bucket.frontend.id}"

    allowed_methods = ["GET", "HEAD", "OPTIONS"]
    cached_methods  = ["GET", "HEAD"]

    # AWS Managed CachingOptimized Policy (ID: 658327ea-f89d-4fab-a63d-7e88639e58f6)
    cache_policy_id = "658327ea-f89d-4fab-a63d-7e88639e58f6"

    viewer_protocol_policy = "redirect-to-https"
    compress               = true
  }

  # ── SPA Routing Fallbacks (React Router) ───────────────────────────────────
  custom_error_response {
    error_code            = 403
    response_code         = 200
    response_page_path    = "/index.html"
    error_caching_min_ttl = 10
  }

  custom_error_response {
    error_code            = 404
    response_code         = 200
    response_page_path    = "/index.html"
    error_caching_min_ttl = 10
  }

  restrictions {
    geo_restriction {
      restriction_type = "none" # Staging baseline (no unnecessary geo-fencing)
    }
  }

  viewer_certificate {
    cloudfront_default_certificate = true
  }

  tags = {
    Name = "${var.project_name}-cloudfront-${var.environment}"
  }
}

# ── 4. S3 Bucket Policy (Restricts Access Strictly to CloudFront OAC) ────────
resource "aws_s3_bucket_policy" "frontend" {
  bucket = aws_s3_bucket.frontend.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowCloudFrontServicePrincipalReadOnly"
        Effect = "Allow"
        Principal = {
          Service = "cloudfront.amazonaws.com"
        }
        Action   = "s3:GetObject"
        Resource = "${aws_s3_bucket.frontend.arn}/*"
        Condition = {
          StringEquals = {
            "AWS:SourceArn" = aws_cloudfront_distribution.distribution.arn
          }
        }
      }
    ]
  })
}
