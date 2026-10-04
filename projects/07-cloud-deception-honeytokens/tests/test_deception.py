"""Offline unit tests for Cloud Deception & Honeytoken Lambda."""
import json
import os
import sys
import unittest
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "lambda")))
import honeytoken_alert


class TestHoneytokenAlert(unittest.TestCase):

    def test_enrich_private_ip(self):
        meta = honeytoken_alert.enrich_ip_metadata("10.0.1.50")
        self.assertEqual(meta["location"], "Internal")

    @patch("honeytoken_alert.enrich_ip_metadata")
    @patch("honeytoken_alert.dispatch_deception_alert")
    def test_lambda_handler_s3_trigger(self, mock_dispatch, mock_enrich):
        mock_dispatch.return_value = True
        mock_enrich.return_value = {
            "ip": "198.51.100.23",
            "city": "Dublin",
            "country": "Ireland",
            "org": "Amazon.com",
        }

        event = {
            "detail": {
                "eventName": "GetObject",
                "eventSource": "s3.amazonaws.com",
                "sourceIPAddress": "198.51.100.23",
                "userAgent": "aws-cli/2.15.0",
                "eventTime": "2026-10-04T19:30:00Z",
                "userIdentity": {
                    "arn": "arn:aws:iam::123456789012:user/attacker"
                },
                "requestParameters": {
                    "bucketName": "canary-sec-internal-db-backups",
                    "key": "credentials/production_database_master.env"
                }
            }
        }

        response = honeytoken_alert.lambda_handler(event, None)
        self.assertEqual(response["statusCode"], 200)
        mock_dispatch.assert_called_once()
        call_args, call_kwargs = mock_dispatch.call_args
        title = call_kwargs.get("title") or (call_args[0] if call_args else "")
        details = call_kwargs.get("details") or (call_args[1] if len(call_args) > 1 else {})

        self.assertIn("Decoy Honeytoken", title)
        self.assertEqual(details.get("adversary_ip"), "198.51.100.23")


if __name__ == "__main__":
    unittest.main()
