#!/usr/bin/env python3
"""Attack simulation script: Tripping the AWS Honeytoken Canary.

Demonstrates an adversary discovering leaked credentials or an internal bucket
and attempting unauthorized access, which triggers our deception pipeline.
"""
import argparse
import sys
import boto3
from botocore.exceptions import ClientError


def simulate_s3_exfiltration(bucket_name: str, key_name: str):
    """Simulates an attacker downloading a decoy bait file."""
    print(f"[*] Attacker attempting to exfiltrate decoy file: s3://{bucket_name}/{key_name} ...")
    s3 = boto3.client("s3")
    try:
        response = s3.get_object(Bucket=bucket_name, Key=key_name)
        data = response["Body"].read().decode("utf-8")
        print(f"[!] Adversary successfully downloaded bait data:\n---\n{data}\n---")
        print("[+] S3 Object Access logged by CloudTrail -> EventBridge -> Honey Alert Lambda triggered!")
    except ClientError as e:
        print(f"[+] API Call executed (Logged by CloudTrail): {e}")


def simulate_iam_key_usage(access_key: str, secret_key: str):
    """Simulates an attacker attempting to use a planted decoy IAM access key."""
    print(f"[*] Attacker attempting reconnaissance with leaked key: {access_key} ...")
    sts = boto3.client(
        "sts",
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_key
    )
    try:
        sts.get_caller_identity()
    except ClientError as e:
        print(f"[+] Call completed with expected Access Denied: {e}")
        print("[+] IAM API Call logged by CloudTrail -> EventBridge -> Honey Alert Lambda triggered!")


def main():
    parser = argparse.ArgumentParser(description="Adversary Canary Trigger Simulator")
    parser.add_argument("--bucket", help="Decoy S3 bucket name")
    parser.add_argument("--key", default="credentials/production_database_master.env", help="S3 bait key name")
    parser.add_argument("--access-key", help="Decoy IAM Access Key ID")
    parser.add_argument("--secret-key", help="Decoy IAM Secret Access Key")

    args = parser.parse_args()

    if args.bucket:
        simulate_s3_exfiltration(args.bucket, args.key)
    elif args.access_key and args.secret_key:
        simulate_iam_key_usage(args.access_key, args.secret_key)
    else:
        print("[*] Dry-run demonstration mode:")
        print("    Usage: python trigger_canary.py --bucket <decoy-bucket-name>")
        print("    Usage: python trigger_canary.py --access-key <KEY_ID> --secret-key <SECRET>")


if __name__ == "__main__":
    main()
