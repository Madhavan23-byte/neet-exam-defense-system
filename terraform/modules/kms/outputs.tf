output "symmetric_key_arn" {
  value       = aws_kms_key.symmetric_encryption.arn
  description = "ARN of the symmetric KMS CMK used for AES-256 envelope encryption"
}

output "symmetric_key_id" {
  value       = aws_kms_key.symmetric_encryption.key_id
  description = "Key ID of the symmetric KMS CMK"
}

output "symmetric_alias_arn" {
  value       = aws_kms_alias.symmetric_encryption.arn
  description = "ARN of the alias for the symmetric encryption key"
}

output "asymmetric_signing_key_arn" {
  value       = aws_kms_key.asymmetric_signing.arn
  description = "ARN of the asymmetric Ed25519 KMS key used for digital signing"
}

output "asymmetric_signing_key_id" {
  value       = aws_kms_key.asymmetric_signing.key_id
  description = "Key ID of the asymmetric Ed25519 KMS signing key"
}

output "asymmetric_signing_alias_arn" {
  value       = aws_kms_alias.asymmetric_signing.arn
  description = "ARN of the alias for the asymmetric signing key"
}
