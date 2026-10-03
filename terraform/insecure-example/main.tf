# DELIBERATELY INSECURE - for demonstrating IaC scanning only.
# Do NOT run `terraform apply` on this folder.

resource "aws_security_group" "bad" {
  name        = "open-to-world"
  description = "SSH open to the internet"
  vpc_id      = "vpc-00000000000000000" # placeholder

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"] # flagged by scanners
  }
}

resource "aws_s3_bucket" "bad" {
  bucket = "example-insecure-bucket-placeholder"
}

resource "aws_s3_bucket_acl" "bad" {
  bucket = aws_s3_bucket.bad.id
  acl    = "public-read" # flagged by scanners
}
# No encryption, no versioning, no public access block.
