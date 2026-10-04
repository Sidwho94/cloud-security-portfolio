#!/usr/bin/env python3
"""AWS IAM Least-Privilege & Attack Path Analyzer.

Detects privilege escalation paths, full admin wildcard permissions,
and cross-account trust risks from AWS IAM policies (supports offline JSON files
and live AWS account inspection).
"""
import argparse
import fnmatch
import json
import os
import sys
from typing import Dict, List, Tuple

# Privilege Escalation Attack Patterns (Action combinations that lead to full account takeover)
ESCALATION_VECTORS = [
    {
        "name": "PassRole to EC2 Instance",
        "required_actions": [["iam:passrole"], ["ec2:runinstances"]],
        "description": "Attacker can launch an EC2 instance with an attached high-privilege IAM instance profile and access its temporary credentials via IMDS.",
        "severity": "CRITICAL",
        "mitre_id": "T1078.004",
    },
    {
        "name": "PassRole to Lambda Function",
        "required_actions": [["iam:passrole"], ["lambda:createfunction", "lambda:invokefunction"]],
        "description": "Attacker can create a Lambda function attached to an admin execution role and trigger code execution to gain admin access.",
        "severity": "CRITICAL",
        "mitre_id": "T1059.006",
    },
    {
        "name": "Create New Default Policy Version",
        "required_actions": [["iam:createpolicyversion"]],
        "description": "Attacker can create a new version of an IAM customer policy granting AdministratorAccess and immediately set it as default.",
        "severity": "CRITICAL",
        "mitre_id": "T1098",
    },
    {
        "name": "Set Default Policy Version",
        "required_actions": [["iam:setdefaultpolicyversion"]],
        "description": "Attacker can switch an existing policy to a previously created dormant high-privilege version.",
        "severity": "HIGH",
        "mitre_id": "T1098",
    },
    {
        "name": "Attach User/Group/Role Policy",
        "required_actions": [["iam:attachuserpolicy", "iam:attachgrouppolicy", "iam:attachrolepolicy"]],
        "description": "Attacker can attach an existing managed policy like 'AdministratorAccess' directly to their own identity.",
        "severity": "CRITICAL",
        "mitre_id": "T1098",
    },
    {
        "name": "Put Inline User/Group/Role Policy",
        "required_actions": [["iam:putuserpolicy", "iam:putgrouppolicy", "iam:putrolepolicy"]],
        "description": "Attacker can inject an arbitrary inline policy granting full administrative privileges.",
        "severity": "CRITICAL",
        "mitre_id": "T1098",
    },
    {
        "name": "Create Access Key for Another User",
        "required_actions": [["iam:createaccesskey"]],
        "description": "Attacker can generate programmatic access keys for target administrative accounts.",
        "severity": "HIGH",
        "mitre_id": "T1098.001",
    },
    {
        "name": "Update User Console Login Profile",
        "required_actions": [["iam:updateloginprofile", "iam:createloginprofile"]],
        "description": "Attacker can reset or create console passwords for other users, including administrators.",
        "severity": "CRITICAL",
        "mitre_id": "T1098",
    },
]


def action_matches(granted_action: str, target_action: str) -> bool:
    """Checks if a granted action string (with potential wildcards) matches a target action."""
    granted = granted_action.lower().strip()
    target = target_action.lower().strip()
    if granted == "*" or granted == "*:*":
        return True
    return fnmatch.fnmatch(target, granted)


def extract_allowed_actions_and_resources(policy_doc: dict) -> List[Tuple[List[str], List[str]]]:
    """Extracts all (allowed_actions, allowed_resources) pairs from policy statements."""
    statements = policy_doc.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]

    allowed_pairs = []
    for stmt in statements:
        if stmt.get("Effect") == "Allow":
            actions = stmt.get("Action", [])
            if isinstance(actions, str):
                actions = [actions]
            resources = stmt.get("Resource", [])
            if isinstance(resources, str):
                resources = [resources]
            allowed_pairs.append((actions, resources))
    return allowed_pairs


def analyze_policy_dict(policy_name: str, policy_doc: dict) -> List[dict]:
    """Analyzes a single IAM policy document and flags risks."""
    findings = []
    statement_pairs = extract_allowed_actions_and_resources(policy_doc)

    # Flatten all allowed actions
    all_allowed_actions = []
    has_wildcard_resource = False

    for actions, resources in statement_pairs:
        all_allowed_actions.extend(actions)
        if "*" in resources:
            has_wildcard_resource = True

    # 1. Check Full Administrator Wildcard (* on *)
    for actions, resources in statement_pairs:
        if ("*" in actions or "*:*" in actions) and ("*" in resources):
            findings.append({
                "policy": policy_name,
                "vector": "Full Administrator Wildcard (* on *)",
                "severity": "CRITICAL",
                "description": "Policy grants unrestricted Action:* on Resource:*, effectively granting root-level permissions.",
                "mitre": "T1078.004",
            })
            break

    # 2. Check for Service-level wildcards on sensitive services
    sensitive_prefixes = ["iam:*", "kms:*", "organizations:*", "sts:*"]
    for prefix in sensitive_prefixes:
        for action in all_allowed_actions:
            if action.lower() == prefix and has_wildcard_resource:
                findings.append({
                    "policy": policy_name,
                    "vector": f"Broad Wildcard on Sensitive Service ({prefix})",
                    "severity": "HIGH",
                    "description": f"Grants blanket access to all API operations in {prefix.split(':')[0]} without granular restriction.",
                    "mitre": "T1068",
                })

    # 3. Check Privilege Escalation Vectors
    for vector in ESCALATION_VECTORS:
        all_requirements_met = True
        for action_group in vector["required_actions"]:
            group_matched = False
            for target_action in action_group:
                if any(action_matches(granted, target_action) for granted in all_allowed_actions):
                    group_matched = True
                    break
            if not group_matched:
                all_requirements_met = False
                break

        if all_requirements_met and has_wildcard_resource:
            findings.append({
                "policy": policy_name,
                "vector": vector["name"],
                "severity": vector["severity"],
                "description": vector["description"],
                "mitre": vector["mitre_id"],
            })

    return findings


def scan_file(filepath: str) -> List[dict]:
    """Scans an offline JSON policy file."""
    with open(filepath, "r", encoding="utf-8") as f:
        policy_data = json.load(f)
    return analyze_policy_dict(os.path.basename(filepath), policy_data)


def scan_directory(dirpath: str) -> List[dict]:
    """Scans all JSON files in a directory."""
    all_findings = []
    for root, _, files in os.walk(dirpath):
        for file in files:
            if file.endswith(".json"):
                full_path = os.path.join(root, file)
                all_findings.extend(scan_file(full_path))
    return all_findings


def scan_aws_live() -> List[dict]:
    """Scans IAM policies in the currently authenticated AWS account."""
    import boto3

    iam = boto3.client("iam")
    all_findings = []
    print("[*] Querying customer-managed policies in AWS account...")
    paginator = iam.get_paginator("list_policies")
    for page in paginator.paginate(Scope="Local"):
        for policy in page.get("Policies", []):
            policy_name = policy["PolicyName"]
            arn = policy["Arn"]
            default_version = policy["DefaultVersionId"]

            version_doc = iam.get_policy_version(
                PolicyArn=arn, VersionId=default_version
            )["PolicyVersion"]["Document"]

            findings = analyze_policy_dict(policy_name, version_doc)
            all_findings.extend(findings)
    return all_findings


def print_report(findings: List[dict]):
    """Prints a structured ASCII report of the findings."""
    print("\n" + "=" * 95)
    print("                      AWS IAM LEAST-PRIVILEGE & ESCALATION AUDIT REPORT")
    print("=" * 95)

    if not findings:
        print("[+] 0 privilege escalation or wildcard vulnerabilities detected. Policies compliant!")
        print("=" * 95 + "\n")
        return

    print(f"Total Security Findings Identified: {len(findings)}\n")
    fmt = "{:<28} {:<10} {:<32} {:<10}"
    print(fmt.format("POLICY NAME", "SEVERITY", "ATTACK VECTOR", "MITRE"))
    print("-" * 95)

    for f in findings:
        print(fmt.format(
            f["policy"][:26],
            f["severity"],
            f["vector"][:30],
            f["mitre"]
        ))
        print(f"  └─ Details: {f['description']}")
        print()
    print("=" * 95 + "\n")


def main():
    parser = argparse.ArgumentParser(description="AWS IAM Least-Privilege & Escalation Analyzer")
    parser.add_argument("--file", help="Path to single JSON policy file")
    parser.add_argument("--dir", help="Path to directory containing JSON policy files")
    parser.add_argument("--live", action="store_true", help="Scan live AWS account using boto3")
    parser.add_argument("--json", action="store_true", help="Output findings in JSON format")

    args = parser.parse_args()

    findings = []
    if args.file:
        findings = scan_file(args.file)
    elif args.dir:
        findings = scan_directory(args.dir)
    elif args.live:
        findings = scan_aws_live()
    else:
        # Default: scan sample_policies folder if it exists
        default_dir = os.path.join(os.path.dirname(__file__), "sample_policies")
        if os.path.exists(default_dir):
            print(f"[*] No arguments provided. Scanning default test policies in {default_dir}...\n")
            findings = scan_directory(default_dir)
        else:
            parser.print_help()
            sys.exit(1)

    if args.json:
        print(json.dumps(findings, indent=2))
    else:
        print_report(findings)

    # Return exit code 1 if critical findings were detected (useful for CI gates)
    has_critical = any(f["severity"] == "CRITICAL" for f in findings)
    sys.exit(1 if has_critical else 0)


if __name__ == "__main__":
    main()
