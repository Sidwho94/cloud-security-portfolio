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

data "aws_caller_identity" "current" {}

# ---------- 1. S3 Decoy / Canary Bucket ----------
resource "aws_s3_bucket" "honey_bucket" {
  bucket        = "${var.name_prefix}-internal-db-backups-${data.aws_caller_identity.current.account_id}"
  force_destroy = true
}

resource "aws_s3_bucket_public_access_block" "honey_bucket" {
  bucket                  = aws_s3_bucket.honey_bucket.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Decoy Bait Files Placed to Trap Adversaries
resource "aws_s3_object" "db_credentials_bait" {
  bucket       = aws_s3_bucket.honey_bucket.id
  key          = "credentials/production_database_master.env"
  content      = "# DECOY HONEYTOKEN - ACCESS IS MONITORED\nDB_HOST=prod-cluster.internal\nDB_USER=masteradmin\nDB_PASS=Sup3rS3cur3P@ssw0rd!#2026\n"
  content_type = "text/plain"
}

resource "aws_s3_object" "customer_export_bait" {
  bucket       = aws_s3_bucket.honey_bucket.id
  key          = "exports/q3_customer_financial_records.csv"
  content      = "id,full_name,ssn,account_balance\n1001,John Doe,XXX-XX-1234,45000.00\n"
  content_type = "text/csv"
}

# ---------- 2. IAM Honeytoken (Decoy User with 0 Permissions) ----------
resource "aws_iam_user" "honey_user" {
  name = "${var.name_prefix}-prod-admin-deployer"
  tags = {
    DeceptionRole = "Honeytoken"
    SecurityClass = "Decoy"
  }
}

resource "aws_iam_access_key" "honey_key" {
  user = aws_iam_user.honey_user.name
}

# Explicit Deny on all actions so the canary cannot do real harm
resource "aws_iam_user_policy" "canary_deny_all" {
  name = "CanaryDenyAll"
  user = aws_iam_user.honey_user.name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Deny"
      Action   = "*"
      Resource = "*"
    }]
  })
}

# ---------- 3. Lambda Alerting Architecture ----------
data "archive_file" "lambda_zip" {
  type        = "zip"
  source_dir  = "${path.module}/../lambda"
  output_path = "${path.module}/build/honeytoken_lambda.zip"
}

resource "aws_iam_role" "honey_alert_role" {
  name = "${var.name_prefix}-alert-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy" "honey_alert_policy" {
  name = "${var.name_prefix}-alert-policy"
  role = aws_iam_role.honey_alert_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = [
        "logs:CreateLogGroup",
        "logs:CreateLogStream",
        "logs:PutLogEvents"
      ]
      Resource = "arn:aws:logs:*:*:*"
    }]
  })
}

resource "aws_lambda_function" "honey_alert" {
  filename         = data.archive_file.lambda_zip.output_path
  source_code_hash = data.archive_file.lambda_zip.output_base64sha256
  function_name    = "${var.name_prefix}-tripwire-alert"
  role             = aws_iam_role.honey_alert_role.arn
  handler          = "honeytoken_alert.lambda_handler"
  runtime          = "python3.11"
  timeout          = 15

  environment {
    variables = {
      ALERT_WEBHOOK_URL = var.alert_webhook_url
    }
  }
}

# ---------- 4. EventBridge Tripwire Rules ----------
# Rule 1: Triggers when any entity reads from the decoy S3 bucket
resource "aws_cloudwatch_event_rule" "s3_honey_trigger" {
  name        = "${var.name_prefix}-s3-tripwire"
  description = "Fires when decoy S3 honeytoken files are accessed"

  event_pattern = jsonencode({
    source      = ["aws.s3"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventSource = ["s3.amazonaws.com"]
      eventName   = ["GetObject", "ListObjects", "ListObjectsV2"]
      requestParameters = {
        bucketName = [aws_s3_bucket.honey_bucket.id]
      }
    }
  })
}

resource "aws_cloudwatch_event_target" "s3_honey_target" {
  rule      = aws_cloudwatch_event_rule.s3_honey_trigger.name
  target_id = "HoneyAlertLambdaS3"
  arn       = aws_lambda_function.honey_alert.arn
}

resource "aws_lambda_permission" "allow_s3_eventbridge" {
  statement_id  = "AllowExecutionFromEventBridgeS3Canary"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.honey_alert.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.s3_honey_trigger.arn
}

# Rule 2: Triggers when the decoy IAM user key is used for any AWS API call
resource "aws_cloudwatch_event_rule" "iam_honey_trigger" {
  name        = "${var.name_prefix}-iam-tripwire"
  description = "Fires when decoy IAM user access key is used anywhere"

  event_pattern = jsonencode({
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      userIdentity = {
        userName = [aws_iam_user.honey_user.name]
      }
    }
  })
}

resource "aws_cloudwatch_event_target" "iam_honey_target" {
  rule      = aws_cloudwatch_event_rule.iam_honey_trigger.name
  target_id = "HoneyAlertLambdaIAM"
  arn       = aws_lambda_function.honey_alert.arn
}

resource "aws_lambda_permission" "allow_iam_eventbridge" {
  statement_id  = "AllowExecutionFromEventBridgeIAMCanary"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.honey_alert.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.iam_honey_trigger.arn
}
