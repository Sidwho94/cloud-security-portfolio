terraform {
  required_version = ">= 1.5"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    archive = {
      source  = "hashicorp/archive"
      version = "~> 2.4"
    }
  }
}

provider "aws" {
  region = var.region
}

# Zip Lambda package
data "archive_file" "lambda_zip" {
  type        = "zip"
  source_dir  = "${path.module}/../lambda"
  output_path = "${path.module}/build/remediation_lambda.zip"
}

# IAM Role for Remediation Lambdas (Least Privilege)
resource "aws_iam_role" "remediation_exec" {
  name = "${var.name_prefix}-remediation-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
    }]
  })
}

resource "aws_iam_policy" "remediation_policy" {
  name        = "${var.name_prefix}-remediation-policy"
  description = "Allows Lambda to enforce S3 Public Access Block and revoke open SG ingress rules"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "S3PublicAccessRemediation"
        Effect   = "Allow"
        Action   = ["s3:PutBucketPublicAccessBlock", "s3:GetBucketPublicAccessBlock"]
        Resource = "arn:aws:s3:::*"
      },
      {
        Sid      = "EC2SecurityGroupRemediation"
        Effect   = "Allow"
        Action   = ["ec2:RevokeSecurityGroupIngress", "ec2:DescribeSecurityGroups"]
        Resource = "*"
      },
      {
        Sid      = "CloudWatchLogging"
        Effect   = "Allow"
        Action   = ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"]
        Resource = "arn:aws:logs:*:*:*"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "remediation_attach" {
  role       = aws_iam_role.remediation_exec.name
  policy_arn = aws_iam_policy.remediation_policy.arn
}

# S3 Remediation Lambda Function
resource "aws_lambda_function" "remediate_s3" {
  filename         = data.archive_file.lambda_zip.output_path
  source_code_hash = data.archive_file.lambda_zip.output_base64sha256
  function_name    = "${var.name_prefix}-remediate-s3-public"
  role             = aws_iam_role.remediation_exec.arn
  handler          = "remediate_s3_public.lambda_handler"
  runtime          = "python3.11"
  timeout          = 30

  environment {
    variables = {
      WEBHOOK_URL = var.alert_webhook_url
    }
  }
}

# SG Remediation Lambda Function
resource "aws_lambda_function" "remediate_sg" {
  filename         = data.archive_file.lambda_zip.output_path
  source_code_hash = data.archive_file.lambda_zip.output_base64sha256
  function_name    = "${var.name_prefix}-remediate-sg-open"
  role             = aws_iam_role.remediation_exec.arn
  handler          = "remediate_sg_open.lambda_handler"
  runtime          = "python3.11"
  timeout          = 30

  environment {
    variables = {
      WEBHOOK_URL = var.alert_webhook_url
    }
  }
}

# EventBridge Rule: S3 Public Exposure Detection
resource "aws_cloudwatch_event_rule" "s3_public_exposure" {
  name        = "${var.name_prefix}-detect-s3-exposure"
  description = "Triggers remediation when S3 bucket ACL or policy is modified"

  event_pattern = jsonencode({
    source      = ["aws.s3"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventSource = ["s3.amazonaws.com"]
      eventName   = ["PutBucketAcl", "PutBucketPolicy", "DeleteBucketPublicAccessBlock"]
    }
  })
}

resource "aws_cloudwatch_event_target" "s3_remediation_target" {
  rule      = aws_cloudwatch_event_rule.s3_public_exposure.name
  target_id = "RemediateS3PublicLambda"
  arn       = aws_lambda_function.remediate_s3.arn
}

resource "aws_lambda_permission" "allow_eventbridge_s3" {
  statement_id  = "AllowExecutionFromEventBridgeS3"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.remediate_s3.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.s3_public_exposure.arn
}

# EventBridge Rule: Security Group Open Ingress Detection
resource "aws_cloudwatch_event_rule" "sg_open_ingress" {
  name        = "${var.name_prefix}-detect-sg-open-ingress"
  description = "Triggers remediation when an ingress rule is added to a security group"

  event_pattern = jsonencode({
    source      = ["aws.ec2"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventSource = ["ec2.amazonaws.com"]
      eventName   = ["AuthorizeSecurityGroupIngress"]
    }
  })
}

resource "aws_cloudwatch_event_target" "sg_remediation_target" {
  rule      = aws_cloudwatch_event_rule.sg_open_ingress.name
  target_id = "RemediateSGOpenLambda"
  arn       = aws_lambda_function.remediate_sg.arn
}

resource "aws_lambda_permission" "allow_eventbridge_sg" {
  statement_id  = "AllowExecutionFromEventBridgeSG"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.remediate_sg.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.sg_open_ingress.arn
}
