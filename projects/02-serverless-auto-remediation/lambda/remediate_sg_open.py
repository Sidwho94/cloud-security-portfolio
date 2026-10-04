"""Lambda function to detect and auto-remediate security groups open to 0.0.0.0/0 on risky ports (22, 3389).

Triggered by EventBridge upon CloudTrail API event: AuthorizeSecurityGroupIngress.
"""
import json
import logging
import boto3
from botocore.exceptions import ClientError
from alert_dispatcher import dispatch_alert

logger = logging.getLogger()
logger.setLevel(logging.INFO)

RISKY_PORTS = {22, 3389}


def revoke_risky_ingress(ec2_client, group_id: str, ip_permissions: list) -> list:
    """Revokes rules that expose risky ports to 0.0.0.0/0."""
    revoked = []
    for perm in ip_permissions:
        from_port = perm.get("fromPort")
        to_port = perm.get("toPort")
        ip_ranges = perm.get("ipRanges", {}).get("items", []) or perm.get("ipRanges", [])

        # Check if 0.0.0.0/0 is included in IP ranges
        has_world_open = any(
            (r.get("cidrIp") == "0.0.0.0/0" or r.get("CidrIp") == "0.0.0.0/0")
            for r in ip_ranges
        )

        if has_world_open and from_port is not None:
            if any(from_port <= p <= to_port for p in RISKY_PORTS):
                try:
                    ec2_client.revoke_security_group_ingress(
                        GroupId=group_id,
                        IpProtocol=perm.get("ipProtocol", "tcp"),
                        FromPort=from_port,
                        ToPort=to_port,
                        CidrIp="0.0.0.0/0"
                    )
                    revoked.append(f"Port {from_port}-{to_port} (0.0.0.0/0)")
                    logger.info(f"Revoked ingress rule on {group_id}: {from_port}-{to_port} from 0.0.0.0/0")
                except ClientError as e:
                    logger.error(f"Failed to revoke rule on {group_id}: {str(e)}")
    return revoked


def lambda_handler(event, context):
    logger.info(f"Received Security Group event: {json.dumps(event)}")
    detail = event.get("detail", {})
    request_params = detail.get("requestParameters", {})
    group_id = request_params.get("groupId")

    if not group_id:
        logger.warning("No groupId in request parameters.")
        return {"statusCode": 400, "body": "Missing groupId"}

    ip_permissions = request_params.get("ipPermissions", {}).get("items", [])
    if not ip_permissions:
        return {"statusCode": 200, "body": "No ipPermissions to evaluate"}

    ec2_client = boto3.client("ec2")
    revoked_rules = revoke_risky_ingress(ec2_client, group_id, ip_permissions)

    if revoked_rules:
        user_identity = detail.get("userIdentity", {}).get("arn", "Unknown Principal")
        dispatch_alert(
            title=f"Insecure Ingress Rule Auto-Revoked on {group_id}",
            details={
                "security_group_id": group_id,
                "revoked_rules": revoked_rules,
                "actor": user_identity,
                "source_ip": detail.get("sourceIPAddress", "N/A"),
                "eventTime": detail.get("eventTime", ""),
                "action": "Revoked 0.0.0.0/0 ingress for management ports"
            },
            severity="HIGH"
        )
        return {"statusCode": 200, "body": f"Revoked: {', '.join(revoked_rules)}"}

    return {"statusCode": 200, "body": "No risky rules detected"}
