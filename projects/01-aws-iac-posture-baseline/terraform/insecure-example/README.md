# Insecure Example — Scanner Test Harness

This configuration is **deliberately insecure** so the Checkov workflow has something real to catch. 

> [!WARNING]
> Do **NOT** run `terraform apply` or `terraform plan` with real credentials against this folder. It exists purely as static analysis scanner input.

### Deliberate Vulnerabilities Included:
- **`aws_security_group.bad`**: SSH (port 22) open to the public internet (`0.0.0.0/0`).
- **`aws_s3_bucket.bad`**: Unencrypted, unversioned S3 bucket with public read ACL.
