# Control mapping (example)

Maps what this repo implements to common framework themes. Fill in the exact
control IDs from the version of CIS AWS Foundations / NIST CSF you are working with.

| Control theme | Framework area (verify ID) | How it is implemented | Evidence |
|---|---|---|---|
| Audit logging enabled in all regions | CIS AWS Foundations (Logging) / NIST CSF DE.CM | `aws_cloudtrail.main`, multi-region, log validation on | Terraform plan, CloudTrail console |
| Log storage is private and encrypted | CIS (Storage/Logging) / NIST CSF PR.DS | S3 public access block, AES256, versioning | Checkov scan result |
| Strong password policy | CIS (IAM) / NIST CSF PR.AC | `aws_iam_account_password_policy.strict` | Terraform state (sandbox) |
| No unrestricted SSH/RDP | CIS (Networking) / NIST CSF PR.AC | Default SG locked down; `scripts/aws_audit.py` checks for open ports | Audit CSV |
| MFA on all IAM users | CIS (IAM) / NIST CSF PR.AC | Detected by `scripts/aws_audit.py` | Audit CSV |
| Misconfigurations caught pre-deploy | NIST CSF PR.IP | Checkov in GitHub Actions | Workflow run history |

## Accepted risks (documented)

These are the exact Checkov checks suppressed for `terraform/baseline` in
`.github/workflows/iac-scan.yml`, confirmed by running Checkov locally against
the baseline rather than guessed. Each is a deliberate lab/free-tier scope
decision; a production deployment would revisit all of them.

| Check ID | What it wants | Why it's accepted here |
|---|---|---|
| CKV_AWS_145 | S3 bucket encrypted with a KMS CMK | AES256 (SSE-S3) used instead - no KMS key cost/management for a demo |
| CKV_AWS_35 | CloudTrail log encrypted with a KMS CMK | Same reason as above |
| CKV_AWS_18 | S3 access logging enabled on the log bucket | Avoids a second bucket/cost; would add in production |
| CKV_AWS_144 | S3 cross-region replication | Lab scope; no second region/bucket for a demo |
| CKV2_AWS_62 | S3 bucket event notifications | No downstream consumer (SNS/SQS/Lambda) exists in this lab |
| CKV2_AWS_11 | VPC Flow Logs enabled | Avoids extra log storage/cost for a demo VPC with no workloads |
| CKV2_AWS_10 | CloudTrail integrated with CloudWatch Logs | Avoids CloudWatch Logs ingestion cost; S3 delivery is kept |
| CKV_AWS_252 | CloudTrail has an SNS topic for notifications | No on-call/alerting pipeline exists in this lab |
