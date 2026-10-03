# Cloud security portfolio

Small, free-tier-friendly examples linking cloud security, IaC, Python
auditing, and governance/assurance. Built as a demo lab, not production code.

## Contents
- `terraform/baseline/` - secure AWS baseline (region `eu-west-2`): private
  encrypted/versioned CloudTrail log bucket, multi-region CloudTrail with log
  file validation, strict IAM account password policy, and a VPC with 2
  private subnets and a locked-down default security group. No NAT gateway -
  the subnets don't need internet egress, which keeps it free-tier friendly.
- `terraform/insecure-example/` - deliberately bad config (open SSH
  `0.0.0.0/0`, public-read/unencrypted/unversioned S3 bucket) used only to
  give the scanner something real to catch. **Never run `terraform apply`
  here.**
- `.github/workflows/iac-scan.yml` - runs Checkov on every pull request that
  touches `terraform/`. The baseline job must pass (with a documented
  skip-check list - see `docs/control-mapping.md`); the insecure-example job
  runs with `soft_fail: true` so it reports findings without blocking the PR.
- `scripts/aws_audit.py` - read-only boto3 audit: public S3 buckets (via
  public access block), IAM users without MFA, access keys older than 90
  days, and security groups open to `0.0.0.0/0` on SSH/RDP. Writes
  `reports/audit_findings.csv` (gitignored - may contain real account data).
- `docs/control-mapping.md` - controls mapped to CIS AWS Foundations / NIST
  CSF themes, with exact control IDs left as placeholders for you to fill in
  from the framework version you're working to. Also documents the real,
  Checkov-verified accepted-risk list for the baseline.
- `docs/risk-register-sample.md` - sample risk register for a fictional
  company, for governance/assurance practice.

## Safety rules
- Keep this repository **private**.
- Never commit access keys, `.tfvars`, state files, real account IDs, or
  generated reports - `.gitignore` covers all of these.
- Run Terraform only in a **sandbox AWS account**: the password policy is
  account-wide.
- Use read-only credentials for the audit script (AWS managed
  `SecurityAudit` policy is enough).
- Set an AWS budget alert, and run `terraform destroy` after each session
  where you actually applied something.
- Cost note: everything here is designed to be free-tier friendly (no NAT
  gateway, no KMS CMKs, small S3 lifecycle expiry). CloudTrail, the VPC, and
  the log bucket cost very little even outside free tier for a lab this
  small, but nothing here is zero-cost once applied.

## Run it

Terraform (format/validate only - this repo's automation never applies):
```bash
cd terraform/baseline
terraform init
terraform fmt -check
terraform validate
terraform plan   # review carefully before ever applying in a sandbox account
```

Python audit script (needs read-only AWS credentials in your environment or
profile - the script never hard-codes or asks for keys):
```bash
cd scripts
python3 -m pip install -r requirements.txt
python3 aws_audit.py
# findings written to reports/audit_findings.csv
```

Checkov locally (optional, same tool the GitHub Actions workflow uses):
```bash
pipx install checkov
checkov -d terraform/baseline            # should pass with the documented skip list
checkov -d terraform/insecure-example --soft-fail   # expected to report findings
```

The skip-check list in `.github/workflows/iac-scan.yml` was built from a
real local Checkov run against the baseline, not guessed - see
`docs/control-mapping.md` for the check IDs and the reasoning behind each
one.
