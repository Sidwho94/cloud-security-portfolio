"""Unit tests for IAM Least-Privilege & Escalation Analyzer."""
import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
import iam_analyzer


class TestIAMAnalyzer(unittest.TestCase):

    def setUp(self):
        self.sample_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "sample_policies"))

    def test_passrole_escalation_detected(self):
        filepath = os.path.join(self.sample_dir, "privilege_escalation_passrole.json")
        findings = iam_analyzer.scan_file(filepath)
        vectors = [f["vector"] for f in findings]
        self.assertIn("PassRole to EC2 Instance", vectors)

    def test_policy_version_escalation_detected(self):
        filepath = os.path.join(self.sample_dir, "privilege_escalation_policyversion.json")
        findings = iam_analyzer.scan_file(filepath)
        vectors = [f["vector"] for f in findings]
        self.assertIn("Create New Default Policy Version", vectors)
        self.assertIn("Set Default Policy Version", vectors)

    def test_wildcard_admin_detected(self):
        filepath = os.path.join(self.sample_dir, "wildcard_admin_policy.json")
        findings = iam_analyzer.scan_file(filepath)
        vectors = [f["vector"] for f in findings]
        self.assertIn("Full Administrator Wildcard (* on *)", vectors)

    def test_compliant_policy_has_zero_findings(self):
        filepath = os.path.join(self.sample_dir, "compliant_least_privilege.json")
        findings = iam_analyzer.scan_file(filepath)
        self.assertEqual(len(findings), 0)


if __name__ == "__main__":
    unittest.main()
