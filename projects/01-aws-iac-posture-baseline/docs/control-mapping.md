# Control Mapping & Compliance Framework

Maps technical controls implemented in this project to industry frameworks (**CIS AWS Foundations Benchmark v3.0** & **NIST Cybersecurity Framework (CSF) v2.0**).

| Control Theme | Framework Area | How It Is Implemented | Evidence |
|---|---|---|---|
| **Multi-Region Audit Logging** | CIS 3.1 / NIST CSF DE.CM-1 | `aws_cloudtrail.main`, multi-region enabled, log validation active | Terraform plan, CloudTrail console |
| **Secure Log Storage** | CIS 3.3 / NIST CSF PR.DS-1 | S3 public access block, AES256 server-side encryption, versioning enabled | Checkov scan result, S3 configuration |
| **IAM Password Policy** | CIS 1.5 - 1.11 / NIST CSF PR.AC-1 | `aws_iam_account_password_policy.strict` (14+ chars, symbols, rotation, reuse prevention) | Terraform state (sandbox) |
| **Restricted Management Access** | CIS 5.2 / NIST CSF PR.AC-5 | Default Security Group locked down (no ingress/egress); `scripts/aws_audit.py` scans for open SSH/RDP | Audit CSV report, Checkov |
| **IAM Multi-Factor Authentication** | CIS 1.10 / NIST CSF PR.AC-6 | Detected by `scripts/aws_audit.py` across all IAM users | `reports/audit_findings.csv` |
| **Pre-Deployment IaC Scanning** | NIST CSF PR.PS-01 | Checkov static analysis in CI/CD pipeline | GitHub Actions workflow runs |

---

## Accepted Risks (Documented)

The following Checkov checks are explicitly suppressed for `terraform/baseline` in `.github/workflows/iac-scan.yml`. Every exclusion is a deliberate cost/lab optimization; in an enterprise production environment, these would be remediated.

| Check ID | Description | Rationale for Lab Environment |
|---|---|---|
| `CKV_AWS_145` | S3 bucket encrypted with KMS Customer Managed Key (CMK) | AES256 (SSE-S3) is used instead to eliminate KMS monthly key charges ($1/key/month) in free tier. |
| `CKV_AWS_35` | CloudTrail logs encrypted with KMS CMK | Same rationale as above; standard SSE-S3 encryption is applied at zero additional cost. |
| `CKV_AWS_18` | S3 access logging enabled on the log bucket | Avoids provisioning an auxiliary logging bucket and storage charges. |
| `CKV_AWS_144` | S3 cross-region replication | Out of scope for single-region lab; avoids cross-region egress and duplicated storage fees. |
| `CKV2_AWS_62` | S3 bucket event notifications | No downstream consumer (SNS/SQS/Lambda) is required for static audit logging in baseline. |
| `CKV2_AWS_11` | VPC Flow Logs enabled | Avoids CloudWatch Logs ingestion fees for a demo VPC hosting zero compute instances. |
| `CKV2_AWS_10` | CloudTrail integrated with CloudWatch Logs | Avoids CloudWatch log group ingestion costs; logs are delivered directly to S3. |
| `CKV_AWS_252` | CloudTrail SNS notifications | No on-call notification pipeline is required for the baseline state. |
