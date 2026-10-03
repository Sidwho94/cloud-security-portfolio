# Sample risk register (fictional company: "Example Ltd")

| ID | Risk | Likelihood | Impact | Rating | Treatment | Owner | Status |
|---|---|---|---|---|---|---|---|
| R1 | Public S3 bucket exposes customer data | Medium | High | High | Mitigate: account-level public access block, automated audit | Cloud lead | Open |
| R2 | IAM users without MFA are compromised | Medium | High | High | Mitigate: enforce MFA, quarterly review | Security lead | Open |
| R3 | Admin access keys never rotated | High | Medium | High | Mitigate: 90-day rotation, alert on age | Cloud lead | Open |
| R4 | Log bucket cost vs. KMS key | Low | Low | Low | Accept: documented in control mapping | CISO | Accepted |
