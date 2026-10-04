"""Lambda function triggered when an adversary touches an AWS Honeytoken (Decoy S3 Bucket or Decoy IAM Key).

Dispatches an immediate high-priority alert with attacker IP, User-Agent, and geolocation details.
"""
import json
import logging
import os
import urllib.request

logger = logging.getLogger()
logger.setLevel(logging.INFO)


def enrich_ip_metadata(ip_address: str) -> dict:
    """Enriches public IP address with approximate geolocation and ASN data."""
    if not ip_address or ip_address in ("127.0.0.1", "localhost") or ip_address.startswith("10.") or ip_address.startswith("192.168."):
        return {"ip": ip_address, "network": "Private/Local Network", "location": "Internal"}

    try:
        url = f"https://ipapi.co/{ip_address}/json/"
        req = urllib.request.Request(url, headers={"User-Agent": "SecurityCanaryEnrichment/1.0"})
        with urllib.request.urlopen(req, timeout=3) as resp:
            if resp.status == 200:
                data = json.loads(resp.read().decode("utf-8"))
                return {
                    "ip": ip_address,
                    "city": data.get("city", "Unknown"),
                    "country": data.get("country_name", "Unknown"),
                    "org": data.get("org", "Unknown"),
                }
    except Exception as e:
        logger.warning(f"Could not enrich IP {ip_address}: {str(e)}")

    return {"ip": ip_address, "location": "Unknown External IP"}


def dispatch_deception_alert(title: str, details: dict) -> bool:
    """Dispatches a critical deception alert to Slack/Teams/Discord or CloudWatch."""
    webhook_url = os.environ.get("ALERT_WEBHOOK_URL")

    payload = {
        "alert_type": "DECEPTION_TRIPWIRE_TRIGGERED",
        "severity": "CRITICAL",
        "title": f"🚨 [TRIPWIRE] {title}",
        "summary": "An adversary or unauthorized entity accessed a decoy honeytoken resource.",
        "incident_details": details,
        "recommendation": "IMMEDIATE INCIDENT RESPONSE: Block the source IP at WAF/VPC and investigate the identity."
    }

    logger.critical("DECEPTION ALERT: %s", json.dumps(payload))

    if not webhook_url:
        logger.info("ALERT_WEBHOOK_URL not configured. Alert logged to CloudWatch.")
        return True

    try:
        req = urllib.request.Request(
            webhook_url,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"}
        )
        with urllib.request.urlopen(req, timeout=5) as res:
            return res.status in (200, 204)
    except Exception as e:
        logger.error(f"Failed to deliver alert to webhook: {str(e)}")
        return False


def lambda_handler(event, context):
    logger.info(f"Received Honeytoken Trigger Event: {json.dumps(event)}")
    detail = event.get("detail", {})

    event_name = detail.get("eventName", "UnknownEvent")
    event_source = detail.get("eventSource", "UnknownSource")
    source_ip = detail.get("sourceIPAddress", "UnknownIP")
    user_agent = detail.get("userAgent", "UnknownAgent")
    user_identity = detail.get("userIdentity", {}).get("arn", "UnknownPrincipal")
    event_time = detail.get("eventTime", "N/A")

    # Determine resource triggered
    request_params = detail.get("requestParameters", {})
    bucket_name = request_params.get("bucketName")
    key_name = request_params.get("key")

    resource_name = f"S3: {bucket_name}/{key_name}" if bucket_name else f"API: {event_source}:{event_name}"

    geo_data = enrich_ip_metadata(source_ip)

    alert_details = {
        "resource_triggered": resource_name,
        "event_action": f"{event_source}:{event_name}",
        "adversary_ip": source_ip,
        "adversary_geo": f"{geo_data.get('city', '')} {geo_data.get('country', '')} ({geo_data.get('org', '')})".strip(),
        "user_agent": user_agent,
        "identity_arn": user_identity,
        "event_time": event_time,
    }

    success = dispatch_deception_alert(
        title=f"Decoy Honeytoken '{resource_name}' Accessed by {source_ip}",
        details=alert_details
    )

    return {
        "statusCode": 200,
        "body": json.dumps({"status": "Alert Dispatched", "success": success})
    }
