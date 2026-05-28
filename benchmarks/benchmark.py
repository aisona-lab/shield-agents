#!/usr/bin/env python3
"""
Benchmark Suite for Shield Agents.

Tests the scanner against known vulnerable code samples to verify
detection accuracy. Uses OWASP WebGoat-inspired test cases and
other standard vulnerability benchmarks.

Usage:
    python -m benchmarks.benchmark
    python -m benchmarks.benchmark --verbose
    python -m benchmarks.benchmark --category injection
"""

import asyncio
import json
import logging
import os
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from shield_agents.config import ShieldConfig
from shield_agents.orchestrator import Orchestrator
from shield_agents.scanners import SASTScanner, SecretsScanner

logger = logging.getLogger("shield_agents.benchmark")


@dataclass
class BenchmarkCase:
    """A single benchmark test case."""
    name: str
    category: str
    code: str
    language: str
    expected_findings: List[str]  # Expected vulnerability categories
    expected_min_severity: str = "MEDIUM"
    description: str = ""


@dataclass
class BenchmarkResult:
    """Result of running a benchmark case."""
    name: str
    category: str
    passed: bool
    detected_categories: List[str]
    expected_categories: List[str]
    missed_categories: List[str]
    false_positives: List[str]
    findings_count: int
    duration: float
    details: str = ""


# =============================================================================
# Benchmark Test Cases - Based on OWASP WebGoat and real-world vulnerabilities
# =============================================================================

BENCHMARK_CASES: List[BenchmarkCase] = [
    # --- SQL Injection ---
    BenchmarkCase(
        name="sql_injection_string_concat",
        category="injection",
        language="python",
        code='''import sqlite3

def get_user(username):
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE username = '" + username + "'"
    cursor.execute(query)
    return cursor.fetchone()

def search_products(term):
    conn = sqlite3.connect("shop.db")
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM products WHERE name LIKE '%{term}%'")
    return cursor.fetchall()
''',
        expected_findings=["injection", "sql_injection"],
        description="SQL injection via string concatenation and f-strings",
    ),
    BenchmarkCase(
        name="sql_injection_format",
        category="injection",
        language="python",
        code='''from django.db import connection

def lookup_user(user_id):
    cursor = connection.cursor()
    cursor.execute("SELECT * FROM auth_user WHERE id = %s" % user_id)
    return cursor.fetchone()

def raw_query(table):
    cursor = connection.cursor()
    cursor.raw("SELECT * FROM {}".format(table))
''',
        expected_findings=["injection", "sql_injection"],
        description="SQL injection via % formatting and .format()",
    ),

    # --- XSS ---
    BenchmarkCase(
        name="xss_dom_based",
        category="xss",
        language="javascript",
        code='''function displaySearchResults() {
    const params = new URLSearchParams(window.location.search);
    const query = params.get('q');
    document.getElementById('results').innerHTML = query;
}

function logAction(action) {
    document.write('<p>Action: ' + action + '</p>');
}
''',
        expected_findings=["xss"],
        description="DOM-based XSS via innerHTML and document.write",
    ),
    BenchmarkCase(
        name="xss_template_injection",
        category="xss",
        language="python",
        code='''from flask import Flask, request, render_template_string

app = Flask(__name__)

@app.route('/greet')
def greet():
    name = request.args.get('name', 'World')
    template = f"<h1>Hello {name}!</h1>"
    return render_template_string(template)

@app.route('/profile')
def profile():
    bio = request.args.get('bio', '')
    return f"<div>{bio | safe}</div>"
''',
        expected_findings=["xss", "injection"],
        description="Server-side XSS via template injection and |safe filter",
    ),

    # --- Command Injection ---
    BenchmarkCase(
        name="command_injection_os_system",
        category="injection",
        language="python",
        code='''import os
import subprocess

def ping_host(host):
    os.system(f"ping -c 4 {host}")

def run_tool(input_file):
    subprocess.call(f"convert {input_file} output.png", shell=True)

def execute_command(cmd):
    subprocess.Popen(cmd, shell=True)
''',
        expected_findings=["injection", "command_injection"],
        description="OS command injection via os.system and subprocess with shell=True",
    ),

    # --- Path Traversal ---
    BenchmarkCase(
        name="path_traversal_open",
        category="path-traversal",
        language="python",
        code='''from flask import Flask, request, send_file

app = Flask(__name__)

@app.route('/download')
def download_file():
    filename = request.args.get('file')
    with open('/var/files/' + filename, 'r') as f:
        return f.read()

@app.route('/view')
def view_file():
    path = request.args.get('path')
    return send_file(path)
''',
        expected_findings=["path-traversal"],
        description="Path traversal via user-controlled file paths",
    ),

    # --- Insecure Deserialization ---
    BenchmarkCase(
        name="insecure_deserialization_pickle",
        category="deserialization",
        language="python",
        code='''import pickle
import yaml

def load_session(data):
    return pickle.loads(data)

def load_config(content):
    return yaml.load(content)  # Missing Loader parameter

def load_cache(raw):
    import marshal
    return marshal.loads(raw)
''',
        expected_findings=["deserialization"],
        description="Insecure deserialization via pickle, yaml, and marshal",
    ),

    # --- Weak Cryptography ---
    BenchmarkCase(
        name="weak_cryptography",
        category="cryptography",
        language="python",
        code='''import hashlib
import random

def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()

def generate_token():
    return str(random.randint(100000, 999999))

def hash_data(data):
    return hashlib.sha1(data.encode()).hexdigest()
''',
        expected_findings=["cryptography"],
        description="Weak cryptography: MD5, SHA1, and random module for security",
    ),

    # --- Hardcoded Secrets ---
    BenchmarkCase(
        name="hardcoded_secrets",
        category="credentials",
        language="python",
        code='''# Database configuration
DB_HOST = "db.prodserver.com"
DB_PASSWORD = "SuperSecret123!"
API_KEY = "PLACEHOLDER_STRIPE_KEY_FOR_TESTING_ONLY"

import requests

def call_api():
    headers = {"Authorization": "Bearer PLACEHOLDER_JWT_TOKEN_FOR_TESTING_ONLY"}
    return requests.get("https://api.example.com/data", headers=headers)

AWS_ACCESS_KEY = "PLACEHOLDER_AWS_KEY_FOR_TESTING_ONLY"
AWS_SECRET_KEY = "PLACEHOLDER_AWS_SECRET_FOR_TESTING_ONLY"
''',
        expected_findings=["credentials", "cloud-credentials", "auth-tokens", "generic-secrets"],
        description="Hardcoded passwords, API keys, JWTs, and AWS credentials",
    ),

    # --- SSL/TLS Issues ---
    BenchmarkCase(
        name="ssl_verification_disabled",
        category="security-misconfiguration",
        language="python",
        code='''import requests
import ssl

def fetch_data(url):
    return requests.get(url, verify=False)

def create_context():
    ctx = ssl._create_unverified_context()
    return ctx

def disable_cert_check():
    ssl._create_default_https_context = ssl._create_unverified_context
''',
        expected_findings=["security-misconfiguration"],
        description="SSL/TLS certificate verification disabled",
    ),

    # --- SSRF ---
    BenchmarkCase(
        name="ssrf_requests",
        category="ssrf",
        language="python",
        code='''import requests
from flask import Flask, request

app = Flask(__name__)

@app.route('/fetch')
def fetch_url():
    url = request.args.get('url')
    response = requests.get(url)
    return response.text

@app.route('/proxy')
def proxy_request():
    target = request.args.get('target')
    return requests.post(target, data=request.form).text
''',
        expected_findings=["ssrf"],
        description="SSRF via user-controlled URL in requests",
    ),

    # --- Auth Issues ---
    BenchmarkCase(
        name="auth_bypass",
        category="authentication",
        language="python",
        code='''from flask import Flask, session

app = Flask(__name__)

@app.route('/admin')
def admin_panel():
    assert session.get('is_admin')
    return "Admin panel"

@app.route('/login', methods=['POST'])
def login():
    session['authenticated'] = True
    return "Logged in"
''',
        expected_findings=["authentication"],
        description="Auth bypass via assertion and session manipulation",
    ),

    # --- Clean Code (should have minimal findings) ---
    BenchmarkCase(
        name="clean_code_minimal_findings",
        category="clean",
        language="python",
        code='''import os
import hashlib
import secrets
from typing import Optional

def get_database_url() -> str:
    """Get database URL from environment variable."""
    return os.environ.get("DATABASE_URL", "sqlite:///default.db")

def hash_password(password: str, salt: Optional[bytes] = None) -> str:
    """Hash password using SHA-256 with salt."""
    if salt is None:
        salt = secrets.token_bytes(32)
    return hashlib.sha256(salt + password.encode()).hexdigest()

def generate_session_token() -> str:
    """Generate a cryptographically secure session token."""
    return secrets.token_urlsafe(32)

def validate_input(data: str, max_length: int = 1000) -> str:
    """Validate and sanitize user input."""
    if len(data) > max_length:
        raise ValueError(f"Input exceeds maximum length of {max_length}")
    return data.strip()
''',
        expected_findings=[],  # Clean code should have no findings
        description="Clean, secure code that should produce minimal/no findings",
    ),
]


class BenchmarkRunner:
    """Run benchmark test cases against Shield Agents."""

    def __init__(self, config: Optional[ShieldConfig] = None):
        self.config = config or ShieldConfig()
        self.results: List[BenchmarkResult] = []

    async def run_all(self, category: Optional[str] = None, verbose: bool = False) -> List[BenchmarkResult]:
        """Run all benchmark cases.

        Args:
            category: Only run cases in this category.
            verbose: Print detailed output.

        Returns:
            List of benchmark results.
        """
        cases = BENCHMARK_CASES
        if category:
            cases = [c for c in cases if c.category == category]

        print(f"\n{'='*60}")
        print(f"Shield Agents Benchmark Suite")
        print(f"Running {len(cases)} test cases...")
        print(f"{'='*60}\n")

        for case in cases:
            result = await self.run_case(case, verbose)
            self.results.append(result)
            status = "PASS" if result.passed else "FAIL"
            print(f"  [{status}] {case.name} ({case.category})")
            if not result.passed and verbose:
                print(f"         Expected: {result.expected_categories}")
                print(f"         Detected: {result.detected_categories}")
                print(f"         Missed:   {result.missed_categories}")
                if result.false_positives:
                    print(f"         False +:  {result.false_positives}")

        return self.results

    async def run_case(self, case: BenchmarkCase, verbose: bool = False) -> BenchmarkResult:
        """Run a single benchmark case.

        Args:
            case: Benchmark case to run.
            verbose: Print detailed output.

        Returns:
            Benchmark result.
        """
        start_time = time.time()

        # Create a temporary file with the test code
        import tempfile
        with tempfile.NamedTemporaryFile(
            mode="w",
            suffix=f".{case.language == 'javascript' and 'js' or case.language}",
            delete=False,
        ) as f:
            f.write(case.code)
            temp_path = f.name

        try:
            # Run scanners
            sast = SASTScanner(self.config)
            secrets = SecretsScanner(self.config)

            sast_findings = sast.scan_file(temp_path)
            secrets_findings = secrets.scan_file(temp_path)

            all_findings = sast_findings + secrets_findings

            # Extract detected categories
            detected = set()
            for finding in all_findings:
                cat = finding.get("category", "").lower()
                detected.add(cat)
                # Also add broader categories from title
                title = finding.get("title", "").lower()
                if "sql" in title:
                    detected.add("sql_injection")
                    detected.add("injection")
                if "xss" in title:
                    detected.add("xss")
                if "command" in title or "os system" in title:
                    detected.add("command_injection")
                    detected.add("injection")

            expected = set(c.lower() for c in case.expected_findings)
            missed = expected - detected
            false_positives = detected - expected - {"generic-secrets", "credentials"}  # Allow some flexibility

            # A case passes if we detect at least one expected finding
            # (or for clean code, if we detect no expected findings)
            if not expected:
                # Clean code - should have no high/critical findings
                high_severity = [f for f in all_findings if f.get("severity", "").upper() in ("CRITICAL", "HIGH")]
                passed = len(high_severity) == 0
            else:
                passed = len(missed) < len(expected)  # At least some expected findings detected

            duration = time.time() - start_time

            return BenchmarkResult(
                name=case.name,
                category=case.category,
                passed=passed,
                detected_categories=sorted(list(detected)),
                expected_categories=sorted(list(expected)),
                missed_categories=sorted(list(missed)),
                false_positives=sorted(list(false_positives)),
                findings_count=len(all_findings),
                duration=duration,
            )

        finally:
            os.unlink(temp_path)

    def print_summary(self):
        """Print a summary of all benchmark results."""
        total = len(self.results)
        passed = sum(1 for r in self.results if r.passed)
        failed = total - passed

        print(f"\n{'='*60}")
        print(f"Benchmark Summary")
        print(f"{'='*60}")
        print(f"Total:  {total}")
        print(f"Passed: {passed}")
        print(f"Failed: {failed}")
        print(f"Rate:   {(passed/total*100):.1f}%" if total > 0 else "Rate: N/A")

        if failed > 0:
            print(f"\nFailed cases:")
            for r in self.results:
                if not r.passed:
                    print(f"  - {r.name} (missed: {r.missed_categories})")

        # Category breakdown
        categories = {}
        for r in self.results:
            cat = r.category
            if cat not in categories:
                categories[cat] = {"passed": 0, "failed": 0}
            if r.passed:
                categories[cat]["passed"] += 1
            else:
                categories[cat]["failed"] += 1

        print(f"\nCategory Breakdown:")
        for cat, stats in sorted(categories.items()):
            total_cat = stats["passed"] + stats["failed"]
            print(f"  {cat}: {stats['passed']}/{total_cat} passed")

        return passed, total


async def main():
    """Main entry point for the benchmark suite."""
    import argparse

    parser = argparse.ArgumentParser(description="Shield Agents Benchmark Suite")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    parser.add_argument("--category", "-c", help="Run only specific category")
    parser.add_argument("--json", action="store_true", help="Output results as JSON")
    args = parser.parse_args()

    runner = BenchmarkRunner()
    await runner.run_all(category=args.category, verbose=args.verbose)
    runner.print_summary()

    if args.json:
        results_json = []
        for r in runner.results:
            results_json.append({
                "name": r.name,
                "category": r.category,
                "passed": r.passed,
                "detected": r.detected_categories,
                "expected": r.expected_categories,
                "missed": r.missed_categories,
                "findings_count": r.findings_count,
            })
        print(json.dumps(results_json, indent=2))


if __name__ == "__main__":
    asyncio.run(main())
