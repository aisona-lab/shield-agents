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
        # AWS's own documentation example key - recognized as non-secret.
        code = '''AWS_KEY = "AKIAIOSFODNN7EXAMPLE"'''
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(code)
            f.flush()
            findings = self.scanner.scan_file(f.name)
        os.unlink(f.name)
        self.assertTrue(any("AWS" in f["title"] for f in findings))

    def test_github_token(self):
        # Build a format-valid but fake token at runtime so no real-looking
        # secret literal is committed (avoids push-protection false alarms).
        fake_token = "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"
        code = f'''GITHUB_TOKEN = "{fake_token}"'''
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
        # Format-valid but fake Stripe secret key, assembled at runtime.
        fake_key = "sk_live_" + "4eC39HqLyjWDarjtT1zdp7dc"
        code = f'''STRIPE_KEY = "{fake_key}"'''
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(code)
            f.flush()
            findings = self.scanner.scan_file(f.name)
        os.unlink(f.name)
        self.assertTrue(any("Stripe" in f["title"] for f in findings))

    def test_jwt_token(self):
        # Format-valid but fake JWT (header.payload.signature), assembled at runtime.
        fake_jwt = "eyJ" + "hbGciOiJIUzI1NiJ9" + ".eyJ" + "zdWIiOiIxMjM0NSJ9" + ".dummysignature0123"
        code = f'''token = "{fake_jwt}"'''
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
