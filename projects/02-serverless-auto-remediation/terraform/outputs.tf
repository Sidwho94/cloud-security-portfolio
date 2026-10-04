output "s3_remediation_lambda_arn" {
  description = "ARN of the S3 auto-remediation Lambda"
  value       = aws_lambda_function.remediate_s3.arn
}

output "sg_remediation_lambda_arn" {
  description = "ARN of the Security Group auto-remediation Lambda"
  value       = aws_lambda_function.remediate_sg.arn
}

output "eventbridge_s3_rule_arn" {
  description = "ARN of EventBridge S3 detection rule"
  value       = aws_cloudwatch_event_rule.s3_public_exposure.arn
}

output "eventbridge_sg_rule_arn" {
  description = "ARN of EventBridge Security Group detection rule"
  value       = aws_cloudwatch_event_rule.sg_open_ingress.arn
}
