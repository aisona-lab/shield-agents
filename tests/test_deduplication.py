"""Tests for the Deduplication Engine."""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from shield_agents.deduplication import FindingDeduplicator


class TestDeduplication(unittest.TestCase):
    """Test the deduplication engine."""

    def setUp(self):
        self.dedup = FindingDeduplicator()

    def test_exact_duplicate_removal(self):
        findings = [
            {"title": "SQL Injection", "file": "app.py", "line": 10, "category": "injection", "source": "SAST", "agent": "SAST"},
            {"title": "SQL Injection", "file": "app.py", "line": 10, "category": "injection", "source": "VulnAgent", "agent": "VulnAgent"},
        ]
        result = self.dedup.deduplicate(findings)
        self.assertEqual(len(result), 1)
        self.assertIn("SAST", result[0]["sources"])
        self.assertIn("VulnAgent", result[0]["sources"])

    def test_different_files_not_deduped(self):
        findings = [
            {"title": "SQL Injection", "file": "app.py", "line": 10, "category": "injection", "source": "SAST", "agent": "SAST"},
            {"title": "SQL Injection", "file": "models.py", "line": 20, "category": "injection", "source": "SAST", "agent": "SAST"},
        ]
        result = self.dedup.deduplicate(findings)
        self.assertEqual(len(result), 2)

    def test_different_categories_not_deduped(self):
        findings = [
            {"title": "SQL Injection", "file": "app.py", "line": 10, "category": "injection", "source": "SAST", "agent": "SAST"},
            {"title": "XSS", "file": "app.py", "line": 15, "category": "xss", "source": "SAST", "agent": "SAST"},
        ]
        result = self.dedup.deduplicate(findings)
        self.assertEqual(len(result), 2)

    def test_severity_escalation(self):
        findings = [
            {"title": "SQL Injection", "file": "app.py", "line": 10, "category": "injection", "severity": "MEDIUM", "source": "SAST", "agent": "SAST"},
            {"title": "SQL Injection", "file": "app.py", "line": 10, "category": "injection", "severity": "CRITICAL", "source": "VulnAgent", "agent": "VulnAgent"},
        ]
        result = self.dedup.deduplicate(findings)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["severity"], "CRITICAL")

    def test_empty_findings(self):
        result = self.dedup.deduplicate([])
        self.assertEqual(len(result), 0)

    def test_stats(self):
        findings = [
            {"title": "SQL Injection", "file": "app.py", "line": 10, "category": "injection", "source": "SAST", "agent": "SAST"},
            {"title": "SQL Injection", "file": "app.py", "line": 10, "category": "injection", "source": "VulnAgent", "agent": "VulnAgent"},
        ]
        self.dedup.deduplicate(findings)
        stats = self.dedup.get_stats()
        self.assertEqual(stats["total_input"], 2)
        self.assertEqual(stats["final_count"], 1)


if __name__ == "__main__":
    unittest.main()
