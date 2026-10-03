#!/usr/bin/env python3
"""Read-only AWS posture check. Writes findings to reports/audit_findings.csv.

Checks: public S3 buckets, IAM users without MFA, access keys older than 90 days,
security groups open to the world on SSH/RDP.
Needs read-only credentials (e.g. the AWS managed SecurityAudit policy).
Never hard-code keys; boto3 reads them from your environment or AWS profile.
"""
import csv
import datetime as dt
import os

import boto3
from botocore.exceptions import ClientError

KEY_MAX_AGE_DAYS = 90
RISKY_PORTS = {22, 3389}


def check_s3(s3):
    # Uses the account/bucket public access block as the public-exposure
    # proxy; it does not parse bucket policies or ACLs directly, so a bucket
    # blocked here but with a separately-public policy would be missed.
    findings = []
    for b in s3.list_buckets()["Buckets"]:
        name = b["Name"]
        try:
            cfg = s3.get_public_access_block(Bucket=name)["PublicAccessBlockConfiguration"]
            fully_blocked = all(cfg.values())
        except ClientError:
            fully_blocked = False
        if not fully_blocked:
            findings.append(("S3", name, "Public access block not fully enabled"))
    return findings


def check_iam(iam):
    findings = []
    now = dt.datetime.now(dt.timezone.utc)
    for page in iam.get_paginator("list_users").paginate():
        for user in page["Users"]:
            name = user["UserName"]
            if not iam.list_mfa_devices(UserName=name)["MFADevices"]:
                findings.append(("IAM", name, "No MFA device"))
            for key in iam.list_access_keys(UserName=name)["AccessKeyMetadata"]:
                age = (now - key["CreateDate"]).days
                if key["Status"] == "Active" and age > KEY_MAX_AGE_DAYS:
                    findings.append(("IAM", name, f"Active access key is {age} days old"))
    return findings


def check_security_groups(ec2):
    findings = []
    for page in ec2.get_paginator("describe_security_groups").paginate():
        for sg in page["SecurityGroups"]:
            for rule in sg["IpPermissions"]:
                open_world = any(r.get("CidrIp") == "0.0.0.0/0" for r in rule.get("IpRanges", []))
                lo, hi = rule.get("FromPort"), rule.get("ToPort")
                if open_world and lo is not None and any(lo <= p <= hi for p in RISKY_PORTS):
                    findings.append(("EC2-SG", sg["GroupId"], f"Ports {lo}-{hi} open to 0.0.0.0/0"))
    return findings


def main():
    session = boto3.Session()
    findings = (
        check_s3(session.client("s3"))
        + check_iam(session.client("iam"))
        + check_security_groups(session.client("ec2"))
    )
    os.makedirs("reports", exist_ok=True)
    with open("reports/audit_findings.csv", "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["service", "resource", "finding"])
        w.writerows(findings)
    print(f"{len(findings)} finding(s) written to reports/audit_findings.csv")


if __name__ == "__main__":
    main()
