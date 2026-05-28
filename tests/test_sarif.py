"""Tests for the SARIF output generator."""

import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from shield_agents.report.sarif import SARIFGenerator


class TestSARIFGenerator(unittest.TestCase):
    """Test the SARIF generator."""

    def setUp(self):
        self.generator = SARIFGenerator()

    def test_basic_sarif_structure(self):
        findings = [
            {"title": "SQL Injection", "severity": "CRITICAL", "category": "injection",
             "file": "app.py", "line": 10, "description": "SQL injection found",
             "rule_id": "SAST-001", "source": "SAST", "agent": "SAST", "cwe": "CWE-89"}
        ]
        sarif = self.generator.generate(findings)

        self.assertEqual(sarif["version"], "2.1.0")
        self.assertIn("runs", sarif)
        self.assertEqual(len(sarif["runs"]), 1)
        self.assertIn("tool", sarif["runs"][0])
        self.assertIn("results", sarif["runs"][0])

    def test_sarif_severity_mapping(self):
        findings = [
            {"title": "Critical Issue", "severity": "CRITICAL", "category": "x",
             "rule_id": "R1", "source": "SAST", "agent": "SAST"},
            {"title": "Medium Issue", "severity": "MEDIUM", "category": "x",
             "rule_id": "R2", "source": "SAST", "agent": "SAST"},
        ]
        sarif = self.generator.generate(findings)
        results = sarif["runs"][0]["results"]

        self.assertEqual(results[0]["level"], "error")
        self.assertEqual(results[1]["level"], "warning")

    def test_sarif_file_location(self):
        findings = [
            {"title": "Issue", "severity": "HIGH", "category": "x",
             "file": "/home/user/project/app.py", "line": 42,
             "rule_id": "R1", "source": "SAST", "agent": "SAST"}
        ]
        sarif = self.generator.generate(findings, target_path="/home/user/project")
        result = sarif["runs"][0]["results"][0]

        self.assertIn("locations", result)
        self.assertEqual(result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"], "app.py")
        self.assertEqual(result["locations"][0]["physicalLocation"]["region"]["startLine"], 42)

    def test_sarif_save(self):
        findings = [
            {"title": "Test", "severity": "LOW", "category": "x",
             "rule_id": "R1", "source": "SAST", "agent": "SAST"}
        ]
        with tempfile.NamedTemporaryFile(suffix=".sarif", delete=False) as f:
            path = f.name

        self.generator.save(findings, path)

        with open(path, "r") as f:
            sarif = json.load(f)

        self.assertEqual(sarif["version"], "2.1.0")
        os.unlink(path)


if __name__ == "__main__":
    unittest.main()
