from pathlib import Path
import unittest

from cloud_guardian.analyzer import (
    analyze_dataset,
    analyze_security_groups,
    is_private_ip,
    risk_rating,
    score_findings,
)


class AnalyzerTests(unittest.TestCase):
    def test_public_admin_security_group_is_critical(self):
        findings = analyze_security_groups(
            [
                {
                    "group_id": "sg-test",
                    "direction": "ingress",
                    "port": "22",
                    "cidr": "0.0.0.0/0",
                }
            ]
        )

        self.assertEqual("critical", findings[0].severity)
        self.assertIn("SSH", findings[0].title)
        self.assertIn("CIS AWS Foundations Benchmark", findings[0].compliance_refs[0])
        self.assertIn("5.2", findings[0].compliance_refs[0])

    def test_private_ip_detection(self):
        self.assertTrue(is_private_ip("10.0.1.10"))
        self.assertFalse(is_private_ip("198.51.100.10"))

    def test_sample_dataset_generates_high_or_critical_report(self):
        project_root = Path(__file__).resolve().parents[1]
        findings, report = analyze_dataset(project_root / "data")

        self.assertGreaterEqual(score_findings(findings), 20)
        self.assertIn(risk_rating(score_findings(findings)), {"High", "Critical"})
        self.assertIn("Admin IAM user without MFA", report)
        self.assertIn("Public SSH access", report)
        self.assertIn("CIS AWS Foundations Benchmark v1.4.0", report)
        self.assertIn("Compliance Coverage", report)


if __name__ == "__main__":
    unittest.main()
