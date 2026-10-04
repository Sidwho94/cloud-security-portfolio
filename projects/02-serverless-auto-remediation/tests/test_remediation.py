"""Unit tests for Serverless Auto-Remediation Lambdas (offline mocked)."""
import json
import os
import sys
import unittest
from unittest.mock import MagicMock, patch

# Add lambda directory to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "lambda")))

import remediate_s3_public
import remediate_sg_open


class TestAutoRemediation(unittest.TestCase):

    def test_s3_remediation_success(self):
        mock_s3 = MagicMock()
        mock_s3.put_public_access_block.return_value = {"ResponseMetadata": {"HTTPStatusCode": 200}}

        res = remediate_s3_public.remediate_bucket(mock_s3, "test-exposed-bucket")
        self.assertTrue(res)
        mock_s3.put_public_access_block.assert_called_once_with(
            Bucket="test-exposed-bucket",
            PublicAccessBlockConfiguration={
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True,
            },
        )

    def test_sg_remediation_revokes_risky_ports(self):
        mock_ec2 = MagicMock()
        mock_ec2.revoke_security_group_ingress.return_value = {"Return": True}

        ip_permissions = [
            {
                "ipProtocol": "tcp",
                "fromPort": 22,
                "toPort": 22,
                "ipRanges": {"items": [{"cidrIp": "0.0.0.0/0"}]},
            },
            {
                "ipProtocol": "tcp",
                "fromPort": 443,
                "toPort": 443,
                "ipRanges": {"items": [{"cidrIp": "0.0.0.0/0"}]},
            },
        ]

        revoked = remediate_sg_open.revoke_risky_ingress(mock_ec2, "sg-12345", ip_permissions)
        # Port 22 should be revoked, Port 443 should NOT be revoked
        self.assertEqual(len(revoked), 1)
        self.assertIn("22-22", revoked[0])
        mock_ec2.revoke_security_group_ingress.assert_called_once_with(
            GroupId="sg-12345",
            IpProtocol="tcp",
            FromPort=22,
            ToPort=22,
            CidrIp="0.0.0.0/0",
        )


if __name__ == "__main__":
    unittest.main()
