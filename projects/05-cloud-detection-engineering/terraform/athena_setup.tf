terraform {
  required_version = ">= 1.5"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.region
}

data "aws_caller_identity" "current" {}

# S3 Bucket for Athena Query Output
resource "aws_s3_bucket" "athena_results" {
  bucket        = "${var.name_prefix}-athena-results-${data.aws_caller_identity.current.account_id}"
  force_destroy = true
}

resource "aws_s3_bucket_public_access_block" "athena_results" {
  bucket                  = aws_s3_bucket.athena_results.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "athena_results" {
  bucket = aws_s3_bucket.athena_results.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "athena_results" {
  bucket = aws_s3_bucket.athena_results.id
  rule {
    id     = "auto-clean-query-results"
    status = "Enabled"
    filter {}
    expiration {
      days = 14
    }
  }
}

# Dedicated Athena Workgroup with enforced cost controls
resource "aws_athena_workgroup" "security_hunting" {
  name        = "${var.name_prefix}-workgroup"
  description = "Dedicated Athena Workgroup for Security Threat Hunting"

  configuration {
    enforce_workgroup_configuration    = true
    publish_cloudwatch_metrics_enabled = true
    bytes_scanned_cutoff_per_query     = 1073741824 # 1 GB query safety limit to eliminate high cost

    result_configuration {
      output_location = "s3://${aws_s3_bucket.athena_results.bucket}/output/"
      encryption_configuration {
        encryption_option = "SSE_S3"
      }
    }
  }
}

# Glue Catalog Database for Security Logs
resource "aws_glue_catalog_database" "security_logs" {
  name        = "security_detection_db"
  description = "Catalog for CloudTrail and VPC Flow Logs"
}
