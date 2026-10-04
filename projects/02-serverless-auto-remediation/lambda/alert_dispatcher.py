"""Alert Dispatcher module for sending security incident alerts via Webhook or SNS."""
import json
import logging
import os
import urllib.request

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)


def dispatch_alert(title: str, details: dict, severity: str = "HIGH") -> bool:
    """Dispatches a structured alert to a configured webhook (Slack/Discord/Teams) or logs it."""
    webhook_url = os.environ.get("WEBHOOK_URL")
    
    payload = {
        "title": f"[{severity}] AWS Security Incident Remediated: {title}",
        "severity": severity,
        "details": details,
        "timestamp": details.get("eventTime", "N/A"),
        "remediation_status": "SUCCESS - Automatically Remediated"
    }

    logger.info("Security alert generated: %s", json.dumps(payload))

    if not webhook_url:
        logger.info("WEBHOOK_URL not configured. Alert logged to CloudWatch only.")
        return True

    try:
        req = urllib.request.Request(
            webhook_url,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"}
        )
        with urllib.request.urlopen(req, timeout=5) as response:
            return response.status in (200, 204)
    except Exception as e:
        logger.error("Failed to post alert to webhook: %s", str(e))
        return False
