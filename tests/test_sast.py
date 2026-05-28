"""Tests for the SAST scanner."""

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from shield_agents.scanners.sast import SASTScanner, SAST_RULES


class TestSASTScanner(unittest.TestCase):
    """Test the SAST scanner."""

    def setUp(self):
        self.scanner = SASTScanner()

    def test_sql_injection_string_concat(self):
        code = '''cursor.execute("SELECT * FROM users WHERE id = " + user_id)'''
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(code)
            f.flush()
            findings = self.scanner.scan_file(f.name)
        os.unlink(f.name)
        self.assertTrue(any("SQL" in f["title"] for f in findings))

    def test_sql_injection_fstring(self):
        code = '''cursor.execute(f"SELECT * FROM users WHERE name = '{name}'")'''
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(code)
            f.flush()
            findings = self.scanner.scan_file(f.name)
        os.unlink(f.name)
        self.assertTrue(any("SQL" in f["title"] for f in findings))

    def test_xss_innerhtml(self):
        code = '''element.innerHTML = userInput;'''
        with tempfile.NamedTemporaryFile(mode="w", suffix=".js", delete=False) as f:
            f.write(code)
            f.flush()
            findings = self.scanner.scan_file(f.name)
        os.unlink(f.name)
        self.assertTrue(any("XSS" in f["title"] for f in findings))

    def test_command_injection(self):
        code = '''os.system(f"ping {host}")'''
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(code)
            f.flush()
            findings = self.scanner.scan_file(f.name)
        os.unlink(f.name)
        self.assertTrue(any("Command" in f["title"] for f in findings))

    def test_subprocess_shell_true(self):
        code = '''subprocess.call(cmd, shell=True)'''
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(code)
            f.flush()
            findings = self.scanner.scan_file(f.name)
        os.unlink(f.name)
        self.assertTrue(any("Command" in f["title"] for f in findings))

    def test_insecure_deserialization_pickle(self):
        code = '''data = pickle.loads(user_input)'''
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(code)
            f.flush()
            findings = self.scanner.scan_file(f.name)
        os.unlink(f.name)
        self.assertTrue(any("Deserialization" in f["title"] for f in findings))

    def test_weak_hash_md5(self):
        code = '''hashlib.md5(data.encode()).hexdigest()'''
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(code)
            f.flush()
            findings = self.scanner.scan_file(f.name)
        os.unlink(f.name)
        self.assertTrue(any("Weak" in f["title"] or "Crypto" in f["title"] for f in findings))

    def test_hardcoded_password(self):
        code = '''password = "SuperSecret123!"'''
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(code)
            f.flush()
            findings = self.scanner.scan_file(f.name)
        os.unlink(f.name)
        self.assertTrue(any("Credential" in f["title"] or "Hardcoded" in f["title"] for f in findings))

    def test_ssl_verify_false(self):
        code = '''requests.get(url, verify=False)'''
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(code)
            f.flush()
            findings = self.scanner.scan_file(f.name)
        os.unlink(f.name)
        self.assertTrue(any("SSL" in f["title"] for f in findings))

    def test_ten_rules_exist(self):
        self.assertEqual(len(SAST_RULES), 10)

    def test_clean_code_minimal_findings(self):
        code = '''import os
import hashlib
import secrets

def get_url():
    return os.environ.get("DATABASE_URL")

def hash_data(data):
    return hashlib.sha256(data.encode()).hexdigest()

def generate_token():
    return secrets.token_urlsafe(32)
'''
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(code)
            f.flush()
            findings = self.scanner.scan_file(f.name)
        os.unlink(f.name)
        # Should not find critical/high issues in clean code
        critical_high = [f for f in findings if f["severity"] in ("CRITICAL", "HIGH")]
        self.assertEqual(len(critical_high), 0)


if __name__ == "__main__":
    unittest.main()
