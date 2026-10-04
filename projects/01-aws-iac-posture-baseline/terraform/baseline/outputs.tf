output "log_bucket_name" {
  description = "Name of the private CloudTrail log bucket"
  value       = aws_s3_bucket.logs.id
}

output "cloudtrail_arn" {
  description = "ARN of the multi-region CloudTrail trail"
  value       = aws_cloudtrail.main.arn
}

output "vpc_id" {
  description = "ID of the baseline VPC"
  value       = aws_vpc.main.id
}

output "private_subnet_ids" {
  description = "IDs of the private subnets"
  value       = aws_subnet.private[*].id
}
