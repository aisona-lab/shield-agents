"""
Static Application Security Testing (SAST) Scanner for Shield Agents.

Implements 10 detection rules covering the most common vulnerability categories.
Returns structured findings compatible with the deduplication engine.
"""

import re
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("shield_agents.sast")


@dataclass
class SASTRule:
    """A SAST detection rule."""
    id: str
    name: str
    description: str
    severity: str
    category: str
    cwe: str
    patterns: List[str]
    remediation: str
    languages: List[str] = None

    def __post_init__(self):
        if self.languages is None:
            self.languages = ["*"]


# The 10 SAST detection rules
SAST_RULES: List[SASTRule] = [
    SASTRule(
        id="SAST-001",
        name="SQL Injection",
        description="SQL query constructed with string formatting or concatenation, allowing injection of arbitrary SQL",
        severity="CRITICAL",
        category="injection",
        cwe="CWE-89",
        patterns=[
            r'cursor\.execute\s*\(\s*[f"\'].*(?:\+|%s|\.format|f["\'])',
            r'\.raw\s*\(\s*[f"\'].*(?:\+|%s|\.format|f["\'])',
            r'execute\s*\(\s*[f"\']SELECT.*\+\s*[\w]+',
            r'execute\s*\(\s*[f"\']INSERT.*\+\s*[\w]+',
            r'execute\s*\(\s*[f"\']UPDATE.*\+\s*[\w]+',
            r'execute\s*\(\s*[f"\']DELETE.*\+\s*[\w]+',
            r'f["\'].*SELECT.*FROM.*WHERE.*\{',
            r'f["\'].*INSERT.*INTO.*VALUES.*\{',
        ],
        remediation="Use parameterized queries with placeholders: cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))",
        languages=["python"],
    ),
    SASTRule(
        id="SAST-002",
        name="Cross-Site Scripting (XSS)",
        description="User input reflected in HTML without proper escaping",
        severity="HIGH",
        category="xss",
        cwe="CWE-79",
        patterns=[
            r'innerHTML\s*=',
            r'document\.write\s*\(',
            r'render_template_string\s*\(',
            r'Markup\s*\(',
            r'\|\s*safe\b',
            r'v-html\s*=',
        ],
        remediation="Sanitize user input before rendering. Use textContent instead of innerHTML. Apply output encoding.",
        languages=["javascript", "python", "html"],
    ),
    SASTRule(
        id="SAST-003",
        name="Command Injection",
        description="OS command execution with potentially user-controlled input",
        severity="CRITICAL",
        category="injection",
        cwe="CWE-78",
        patterns=[
            r'os\.system\s*\(',
            r'os\.popen\s*\(',
            r'subprocess\.(call|run|Popen|check_output)\s*\([^)]*shell\s*=\s*True',
            r'subprocess\.(call|run|Popen)\s*\(\s*["\']',
            r'exec\s*\(',
        ],
        remediation="Use subprocess with shell=False and list arguments. Never pass user input to shell commands directly.",
        languages=["python"],
    ),
    SASTRule(
        id="SAST-004",
        name="Path Traversal",
        description="File path constructed with user input, allowing directory traversal",
        severity="HIGH",
        category="path-traversal",
        cwe="CWE-22",
        patterns=[
            r'open\s*\(\s*["\'].*\+\s*\w+',
            r'open\s*\(\s*.*\+\s*request\.',
            r'open\s*\(\s*.*\.format\s*\(.*request\.',
            r'os\.path\.join\s*\([^)]*request\.',
            r'send_file\s*\(\s*request\.',
            r'send_file\s*\([^)]*request\.',
            r'f["\'].*\/.*\{.*request',
            r'["\']/var/[a-z]+/["\']\s*\+\s*\w+',
        ],
        remediation="Validate and sanitize file paths. Use allowlists for permitted directories. Avoid constructing paths from user input.",
        languages=["python", "javascript"],
    ),
    SASTRule(
        id="SAST-005",
        name="Insecure Deserialization",
        description="Deserialization of untrusted data can lead to remote code execution",
        severity="CRITICAL",
        category="deserialization",
        cwe="CWE-502",
        patterns=[
            r'pickle\.loads?\s*\(',
            r'yaml\.load\s*\([^)]*\)(?!.*Loader)',
            r'marshal\.loads?\s*\(',
            r'shelve\.open\s*\(',
        ],
        remediation="Use safe serialization formats like JSON. For YAML, use yaml.safe_load(). Never deserialize untrusted data with pickle.",
        languages=["python"],
    ),
    SASTRule(
        id="SAST-006",
        name="Weak Cryptography",
        description="Use of weak or broken cryptographic algorithms",
        severity="MEDIUM",
        category="cryptography",
        cwe="CWE-327",
        patterns=[
            r'hashlib\.(md5|sha1)\s*\(',
            r'DES|RC4|Blowfish',
            r'MODE_ECB',
            r'random\.(random|randint|choice|shuffle)\s*\((?!.*#.*security)',
            r'cryptography\.hazmat.*MD5',
        ],
        remediation="Use SHA-256 or stronger for hashing. Use AES-GCM or ChaCha20 for encryption. Use secrets module for random values.",
        languages=["python"],
    ),
    SASTRule(
        id="SAST-007",
        name="Authentication Issues",
        description="Weak or improper authentication implementation",
        severity="HIGH",
        category="authentication",
        cwe="CWE-287",
        patterns=[
            r'verify_password\s*=\s*False',
            r'check_password\s*=\s*True',
            r'assert\s+.*authenticated',
            r'@login_required',
            r'session\[.*\]\s*=\s*True(?!.*verify)',
            r'jwt\.decode\s*\([^)]*\)(?!.*algorithms)',
        ],
        remediation="Implement proper authentication checks. Use established authentication libraries. Never bypass auth with assertions.",
        languages=["python"],
    ),
    SASTRule(
        id="SAST-008",
        name="Hardcoded Credentials",
        description="Credentials hardcoded in source code",
        severity="HIGH",
        category="credentials",
        cwe="CWE-798",
        patterns=[
            r'(?:password|passwd|pwd)\s*=\s*["\'][^"\']{4,}["\']',
            r'(?:api_key|apikey|api_secret)\s*=\s*["\'][^"\']{8,}["\']',
            r'(?:secret_key|secretkey|secret)\s*=\s*["\'][^"\']{8,}["\']',
            r'(?:token|auth_token|access_token)\s*=\s*["\'][^"\']{8,}["\']',
            r'(?:database_url|db_password)\s*=\s*["\'][^"\']{8,}["\']',
        ],
        remediation="Move credentials to environment variables or a secure vault. Use os.environ.get() or a secrets manager.",
        languages=["python", "javascript"],
    ),
    SASTRule(
        id="SAST-009",
        name="Insecure SSL/TLS Configuration",
        description="SSL/TLS certificate verification disabled",
        severity="HIGH",
        category="security-misconfiguration",
        cwe="CWE-295",
        patterns=[
            r'verify\s*=\s*False',
            r'ssl\._create_unverified_context',
            r'CERT_NONE',
            r'requests\.get\s*\([^)]*verify\s*=\s*False',
            r'disable.*ssl|disable.*tls|skip.*verification',
        ],
        remediation="Always verify SSL certificates. Never use verify=False in production. Use proper certificate bundles.",
        languages=["python"],
    ),
    SASTRule(
        id="SAST-010",
        name="Server-Side Request Forgery (SSRF)",
        description="Application makes requests to user-specified URLs",
        severity="HIGH",
        category="ssrf",
        cwe="CWE-918",
        patterns=[
            r'requests\.(get|post|put|delete)\s*\(\s*request\.',
            r'requests\.(get|post|put|delete)\s*\([^)]*request\.args',
            r'requests\.(get|post)\s*\(\s*url\s*\)',
            r'urllib\.request\.urlopen\s*\(\s*request\.',
            r'http\.client.*request\.',
            r'fetch\s*\(\s*.*request\.',
            r'urlopen\s*\(\s*.*\.format\s*\(.*request',
            r'return\s+requests\.\w+\([^)]*\)\.text',
        ],
        remediation="Validate URLs against an allowlist. Block requests to internal IPs. Use URL parsing to validate scheme and host.",
        languages=["python", "javascript"],
    ),
]


class SASTScanner:
    """Static Application Security Testing scanner.

    Scans source code files using pattern-based detection rules.
    """

    def __init__(self, config=None):
        self.config = config
        self.rules = SAST_RULES
        self.findings: List[Dict[str, Any]] = []

    def scan_file(self, file_path: str, content: Optional[str] = None) -> List[Dict[str, Any]]:
        """Scan a single file for vulnerabilities.

        Args:
            file_path: Path to the file.
            content: Optional file content (will be read if not provided).

        Returns:
            List of findings for this file.
        """
        from ..utils.helpers import read_file_safe

        if content is None:
            content = read_file_safe(file_path)
            if content is None:
                return []

        file_findings = []
        lines = content.split("\n")

        for rule in self.rules:
            for pattern in rule.patterns:
                try:
                    for match in re.finditer(pattern, content, re.IGNORECASE | re.DOTALL):
                        line_num = content[:match.start()].count("\n") + 1
                        line_content = lines[line_num - 1].strip() if line_num <= len(lines) else match.group(0)

                        # Skip very short matches that are likely false positives
                        if len(match.group(0)) < 3:
                            continue

                        finding = {
                            "id": f"{rule.id}-{len(file_findings) + 1}",
                            "rule_id": rule.id,
                            "title": rule.name,
                            "description": rule.description,
                            "severity": rule.severity,
                            "category": rule.category,
                            "cwe": rule.cwe,
                            "file": file_path,
                            "line": line_num,
                            "code_snippet": line_content[:200],
                            "remediation": rule.remediation,
                            "source": "SAST",
                            "agent": "SASTScanner",
                            "confidence": 0.85,
                        }
                        file_findings.append(finding)
                except re.error:
                    continue

        self.findings.extend(file_findings)
        logger.info(f"SAST: Found {len(file_findings)} issues in {file_path}")
        return file_findings

    def scan_directory(self, directory: str, excluded_dirs: Optional[List[str]] = None) -> List[Dict[str, Any]]:
        """Scan all source files in a directory.

        Args:
            directory: Directory to scan.
            excluded_dirs: Directory names to exclude.

        Returns:
            List of all findings.
        """
        from ..utils.helpers import find_files, read_file_safe

        if excluded_dirs is None:
            excluded_dirs = ["node_modules", ".git", "__pycache__", ".venv", "venv", "dist", "build"]

        source_extensions = [
            ".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".go", ".rb",
            ".php", ".c", ".cpp", ".cs", ".rs", ".swift", ".kt",
            ".html", ".htm", ".xml", ".yaml", ".yml", ".json", ".sql",
        ]

        files = find_files(directory, extensions=source_extensions, exclude_dirs=excluded_dirs)

        all_findings = []
        for file_path in files:
            findings = self.scan_file(file_path)
            all_findings.extend(findings)

        logger.info(f"SAST: Scanned {len(files)} files, found {len(all_findings)} total issues")
        return all_findings

    def clear_findings(self):
        """Clear all findings."""
        self.findings = []
