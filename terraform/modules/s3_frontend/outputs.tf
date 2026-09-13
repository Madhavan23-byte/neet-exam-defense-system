output "s3_bucket_name" {
  value       = aws_s3_bucket.frontend.id
  description = "The name of the private S3 bucket hosting frontend assets"
}

output "s3_bucket_arn" {
  value       = aws_s3_bucket.frontend.arn
  description = "The ARN of the frontend S3 bucket"
}

output "cloudfront_distribution_id" {
  value       = aws_cloudfront_distribution.distribution.id
  description = "The ID of the CloudFront distribution"
}

output "cloudfront_domain_name" {
  value       = aws_cloudfront_distribution.distribution.domain_name
  description = "The domain name of the CloudFront distribution"
}
