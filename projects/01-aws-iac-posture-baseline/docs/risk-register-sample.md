# Sample Risk Register (Fictional Organization: "Example Ltd")

| Risk ID | Threat Scenario | Likelihood | Impact | Inherent Risk | Treatment Strategy | Assigned Owner | Residual Risk | Status |
|---|---|---|---|---|---|---|---|---|
| **R1** | Unrestricted S3 bucket allows unauthorized public read of confidential audit logs | Medium | High | **High** | **Mitigate**: Enable S3 Account Public Access Block; enforce bucket policy conditions; continuous posture auditing. | Cloud Security Lead | Low | Remediated |
| **R2** | Account takeover of IAM user credentials lacking Multi-Factor Authentication (MFA) | High | High | **Critical** | **Mitigate**: Enforce mandatory MFA via IAM conditional policy; script automated detection of non-compliant users. | IAM / SecOps Lead | Low | Open |
| **R3** | Unrotated long-lived programmatic IAM access keys compromised via leak | High | Medium | **High** | **Mitigate**: Enforce 90-day automatic key deactivation and alert pipeline. | Cloud Security Lead | Low | Open |
| **R4** | High monthly KMS CMK costs incurred for low-sensitivity demo lab data | Low | Low | **Low** | **Accept**: Default SSE-S3 AES-256 applied in lieu of customer-managed keys (see control mapping). | CISO | Low | Accepted |
