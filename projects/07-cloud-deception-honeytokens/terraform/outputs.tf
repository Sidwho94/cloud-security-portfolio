output "decoy_bucket_name" {
  description = "Name of the decoy S3 Honeytoken bucket"
  value       = aws_s3_bucket.honey_bucket.id
}

output "decoy_iam_username" {
  description = "Username of the decoy IAM Honeytoken user"
  value       = aws_iam_user.honey_user.name
}

output "decoy_access_key_id" {
  description = "Canary Access Key ID (plant this in fake configs / Git repos)"
  value       = aws_iam_access_key.honey_key.id
}

output "decoy_secret_access_key" {
  description = "Canary Secret Access Key"
  value       = aws_iam_access_key.honey_key.secret
  sensitive   = true
}

output "tripwire_lambda_arn" {
  description = "ARN of the deception alerting Lambda"
  value       = aws_lambda_function.honey_alert.arn
}
