"""Lambda function to detect and remediate publicly exposed S3 buckets.

Triggered by EventBridge upon CloudTrail API events: PutBucketAcl, PutBucketPolicy, DeletePublicAccessBlock.
"""
import json
import logging
import boto3
from botocore.exceptions import ClientError
from alert_dispatcher import dispatch_alert

logger = logging.getLogger()
logger.setLevel(logging.INFO)


def remediate_bucket(s3_client, bucket_name: str) -> bool:
    """Enforces account/bucket level Public Access Block on the offending S3 bucket."""
    try:
        s3_client.put_public_access_block(
            Bucket=bucket_name,
            PublicAccessBlockConfiguration={
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True,
            },
        )
        logger.info(f"Successfully applied Full Public Access Block on bucket: {bucket_name}")
        return True
    except ClientError as e:
        logger.error(f"Error applying public access block to {bucket_name}: {str(e)}")
        return False


def lambda_handler(event, context):
    logger.info(f"Received EventBridge CloudTrail event: {json.dumps(event)}")
    detail = event.get("detail", {})
    event_name = detail.get("eventName", "")
    request_params = detail.get("requestParameters", {})
    bucket_name = request_params.get("bucketName")

    if not bucket_name:
        logger.warning("No bucketName identified in event detail. Exiting.")
        return {"statusCode": 400, "body": "Missing bucketName"}

    s3_client = boto3.client("s3")
    success = remediate_bucket(s3_client, bucket_name)

    if success:
        user_identity = detail.get("userIdentity", {}).get("arn", "Unknown Principal")
        event_time = detail.get("eventTime", "")
        dispatch_alert(
            title=f"Public Exposure on S3 Bucket '{bucket_name}' Neutralized",
            details={
                "bucket": bucket_name,
                "trigger_event": event_name,
                "actor": user_identity,
                "source_ip": detail.get("sourceIPAddress", "N/A"),
                "eventTime": event_time,
                "action": "Enforced PutPublicAccessBlock (All 4 settings enabled)"
            },
            severity="CRITICAL"
        )
        return {"statusCode": 200, "body": f"Bucket {bucket_name} secured"}
    else:
        return {"statusCode": 500, "body": f"Failed to secure bucket {bucket_name}"}
