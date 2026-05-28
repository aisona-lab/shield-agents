"""Tests for the .shieldignore file support."""

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from shield_agents.shieldignore import ShieldIgnore


class TestShieldIgnore(unittest.TestCase):
    """Test the .shieldignore file parser."""

    def test_ignore_by_category(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            ignore_file = os.path.join(tmpdir, ".shieldignore")
            with open(ignore_file, "w") as f:
                f.write("category:information-disclosure\n")

            si = ShieldIgnore(tmpdir)
            si.load()

            finding = {"title": "Info Leak", "category": "information-disclosure", "severity": "LOW"}
            self.assertTrue(si.should_ignore(finding))

    def test_ignore_by_severity(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            ignore_file = os.path.join(tmpdir, ".shieldignore")
            with open(ignore_file, "w") as f:
                f.write("severity:LOW\n")

            si = ShieldIgnore(tmpdir)
            si.load()

            # LOW and INFO should be ignored
            self.assertTrue(si.should_ignore({"severity": "LOW", "title": "test", "category": "x"}))
            self.assertTrue(si.should_ignore({"severity": "INFO", "title": "test", "category": "x"}))
            # MEDIUM should NOT be ignored
            self.assertFalse(si.should_ignore({"severity": "MEDIUM", "title": "test", "category": "x"}))

    def test_ignore_by_file(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            ignore_file = os.path.join(tmpdir, ".shieldignore")
            with open(ignore_file, "w") as f:
                f.write("file:test_app.py\n")

            si = ShieldIgnore(tmpdir)
            si.load()

            self.assertTrue(si.should_ignore({"file": "test_app.py", "title": "x", "category": "x"}))
            self.assertFalse(si.should_ignore({"file": "app.py", "title": "x", "category": "x"}))

    def test_ignore_by_rule_id(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            ignore_file = os.path.join(tmpdir, ".shieldignore")
            with open(ignore_file, "w") as f:
                f.write("rule:SAST-001\n")

            si = ShieldIgnore(tmpdir)
            si.load()

            self.assertTrue(si.should_ignore({"rule_id": "SAST-001", "title": "x", "category": "x"}))
            self.assertFalse(si.should_ignore({"rule_id": "SAST-002", "title": "x", "category": "x"}))

    def test_filter_findings(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            ignore_file = os.path.join(tmpdir, ".shieldignore")
            with open(ignore_file, "w") as f:
                f.write("severity:LOW\n")

            si = ShieldIgnore(tmpdir)
            si.load()

            findings = [
                {"title": "Critical", "severity": "CRITICAL", "category": "x"},
                {"title": "Medium", "severity": "MEDIUM", "category": "x"},
                {"title": "Low", "severity": "LOW", "category": "x"},
            ]
            filtered = si.filter_findings(findings)
            self.assertEqual(len(filtered), 2)

    def test_no_shieldignore_file(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            si = ShieldIgnore(tmpdir)
            si.load()
            # No rules loaded, nothing should be filtered
            self.assertFalse(si.should_ignore({"title": "test", "severity": "LOW", "category": "x"}))

    def test_create_template(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = ShieldIgnore.create_template(tmpdir)
            self.assertTrue(os.path.exists(path))


if __name__ == "__main__":
    unittest.main()
