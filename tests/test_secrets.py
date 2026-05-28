"""Tests for the Secrets scanner."""

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from shield_agents.scanners.secrets import SecretsScanner


class TestSecretsScanner(unittest.TestCase):
    """Test the Secrets scanner."""

    def setUp(self):
        self.scanner = SecretsScanner()

    def test_aws_access_key(self):
        code = '''AWS_KEY = "PLACEHOLDER_AWS_KEY_FOR_TESTING_ONLY"'''
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(code)
            f.flush()
            findings = self.scanner.scan_file(f.name)
        os.unlink(f.name)
        self.assertTrue(any("AWS" in f["title"] for f in findings))

    def test_github_token(self):
        code = '''GITHUB_TOKEN = "PLACEHOLDER_GITHUB_TOKEN_FOR_TESTING_ONLY"'''
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(code)
            f.flush()
            findings = self.scanner.scan_file(f.name)
        os.unlink(f.name)
        self.assertTrue(any("GitHub" in f["title"] for f in findings))

    def test_private_key(self):
        code = '''key = """-----BEGIN RSA PRIVATE KEY-----\nMIIEowI\n-----END RSA PRIVATE KEY-----"""'''
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(code)
            f.flush()
            findings = self.scanner.scan_file(f.name)
        os.unlink(f.name)
        self.assertTrue(any("Private Key" in f["title"] or "RSA" in f["title"] for f in findings))

    def test_database_connection_string(self):
        code = '''DB_URL = "postgres://admin:password123@db.prodserver.com:5432/mydb"'''
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(code)
            f.flush()
            findings = self.scanner.scan_file(f.name)
        os.unlink(f.name)
        self.assertTrue(any("Database" in f["title"] for f in findings))

    def test_stripe_key(self):
        code = '''STRIPE_KEY = "PLACEHOLDER_STRIPE_KEY_FOR_TESTING_ONLY"'''
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(code)
            f.flush()
            findings = self.scanner.scan_file(f.name)
        os.unlink(f.name)
        self.assertTrue(any("Stripe" in f["title"] for f in findings))

    def test_jwt_token(self):
        code = '''token = "PLACEHOLDER_JWT_TOKEN_FOR_TESTING_ONLY"'''
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(code)
            f.flush()
            findings = self.scanner.scan_file(f.name)
        os.unlink(f.name)
        self.assertTrue(any("JWT" in f["title"] or "JSON Web Token" in f["title"] for f in findings))

    def test_masking(self):
        """Verify secrets are masked in output."""
        code = '''password = "MyVerySecretPassword123"'''
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(code)
            f.flush()
            findings = self.scanner.scan_file(f.name)
        os.unlink(f.name)
        # Code snippets should not contain the raw password
        for f in findings:
            if "password" in f.get("code_snippet", "").lower():
                self.assertNotIn("MyVerySecretPassword123", f["code_snippet"])

    def test_clean_code_no_secrets(self):
        code = '''import os
def get_config():
    return os.environ.get("API_KEY")
'''
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(code)
            f.flush()
            findings = self.scanner.scan_file(f.name)
        os.unlink(f.name)
        self.assertEqual(len(findings), 0)


if __name__ == "__main__":
    unittest.main()
