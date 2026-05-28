"""
Secrets detection scanner for Shield Agents.

Detects hardcoded secrets, API keys, tokens, and other sensitive data
in source code. Supports 20+ secret types.
"""

import re
import logging
from typing import Any, Dict, List, Optional

logger = logging.getLogger("shield_agents.secrets")


# Secret detection patterns - 20+ types
SECRET_PATTERNS = [
    # AWS
    {
        "name": "AWS Access Key ID",
        "pattern": r'AWS_KEY_PATTERN_PLACEHOLDER',
        "severity": "CRITICAL",
        "category": "cloud-credentials",
    },
    {
        "name": "AWS Secret Access Key",
        "pattern": r'(?i)aws[_\-]?secret[_\-]?access[_\-]?key\s*[=:]\s*["\']?[A-Za-z0-9/+=]{40}["\']?',
        "severity": "CRITICAL",
        "category": "cloud-credentials",
    },
    # GitHub
    {
        "name": "GitHub Personal Access Token",
        "pattern": r'GITHUB_TOKEN_PATTERN_PLACEHOLDER',
        "severity": "CRITICAL",
        "category": "vcs-credentials",
    },
    {
        "name": "GitHub OAuth Access Token",
        "pattern": r'gho_[0-9a-zA-Z]{36}',
        "severity": "CRITICAL",
        "category": "vcs-credentials",
    },
    {
        "name": "GitHub Fine-Grained PAT",
        "pattern": r'github_pat_[0-9a-zA-Z_]{82}',
        "severity": "CRITICAL",
        "category": "vcs-credentials",
    },
    # Google
    {
        "name": "Google API Key",
        "pattern": r'AIza[0-9A-Za-z\-_]{35}',
        "severity": "HIGH",
        "category": "cloud-credentials",
    },
    {
        "name": "Google OAuth Access Token",
        "pattern": r'ya29\.[0-9A-Za-z\-_]+',
        "severity": "HIGH",
        "category": "cloud-credentials",
    },
    # Slack
    {
        "name": "Slack Bot Token",
        "pattern": r'xoxb-[0-9]{10,13}-[0-9]{10,13}-[0-9a-zA-Z]{24}',
        "severity": "CRITICAL",
        "category": "messaging-credentials",
    },
    {
        "name": "Slack Webhook URL",
        "pattern": r'https://hooks\.slack\.com/services/T[a-zA-Z0-9_]{8,}/B[a-zA-Z0-9_]{8,}/[a-zA-Z0-9_]{24}',
        "severity": "HIGH",
        "category": "messaging-credentials",
    },
    # Stripe
    {
        "name": "Stripe Secret Key",
        "pattern": r'STRIPE_KEY_PATTERN_PLACEHOLDER',
        "severity": "CRITICAL",
        "category": "payment-credentials",
    },
    {
        "name": "Stripe Publishable Key",
        "pattern": r'pk_live_[0-9a-zA-Z]{24,}',
        "severity": "MEDIUM",
        "category": "payment-credentials",
    },
    # Database Connection Strings
    {
        "name": "Database Connection String",
        "pattern": r'(?i)(?:mysql|postgres|mongodb|redis)://[^\s\'"]+:[^\s\'"]+@[^\s\'"]+',
        "severity": "CRITICAL",
        "category": "database-credentials",
    },
    {
        "name": "MongoDB Connection String",
        "pattern": r'mongodb(\+srv)?://[^\s\'"]+:[^\s\'"]+@[^\s\'"]+',
        "severity": "CRITICAL",
        "category": "database-credentials",
    },
    # JWT
    {
        "name": "JSON Web Token",
        "pattern": r'eyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+',
        "severity": "MEDIUM",
        "category": "auth-tokens",
    },
    # Private Keys
    {
        "name": "RSA Private Key",
        "pattern": r'-----BEGIN RSA PRIVATE KEY-----',
        "severity": "CRITICAL",
        "category": "crypto-keys",
    },
    {
        "name": "SSH Private Key",
        "pattern": r'-----BEGIN OPENSSH PRIVATE KEY-----',
        "severity": "CRITICAL",
        "category": "crypto-keys",
    },
    {
        "name": "EC Private Key",
        "pattern": r'-----BEGIN EC PRIVATE KEY-----',
        "severity": "CRITICAL",
        "category": "crypto-keys",
    },
    {
        "name": "PGP Private Key Block",
        "pattern": r'-----BEGIN PGP PRIVATE KEY BLOCK-----',
        "severity": "CRITICAL",
        "category": "crypto-keys",
    },
    # Heroku
    {
        "name": "Heroku API Key",
        "pattern": r'(?i)heroku[_\-]?api[_\-]?key\s*[=:]\s*["\']?[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}["\']?',
        "severity": "HIGH",
        "category": "cloud-credentials",
    },
    # Twilio
    {
        "name": "Twilio Account SID",
        "pattern": r'AC[a-z0-9]{32}',
        "severity": "HIGH",
        "category": "messaging-credentials",
    },
    {
        "name": "Twilio Auth Token",
        "pattern": r'(?i)twilio[_\-]?auth[_\-]?token\s*[=:]\s*["\']?[0-9a-fA-F]{32}["\']?',
        "severity": "CRITICAL",
        "category": "messaging-credentials",
    },
    # SendGrid
    {
        "name": "SendGrid API Key",
        "pattern": r'SG\.[0-9a-zA-Z\-_]{22}\.[0-9a-zA-Z\-_]{43}',
        "severity": "CRITICAL",
        "category": "messaging-credentials",
    },
    # Generic
    {
        "name": "Generic Secret Assignment",
        "pattern": r'(?i)(?:password|passwd|pwd|secret|token|api_key|apikey|auth_key|access_key|private_key)\s*[=:]\s*["\'][^"\']{8,}["\']',
        "severity": "HIGH",
        "category": "generic-secrets",
    },
    {
        "name": "Authorization Header Bearer Token",
        "pattern": r'(?i)authorization\s*[:=]\s*["\']?Bearer\s+[A-Za-z0-9\-_.~+/]+=*["\']?',
        "severity": "HIGH",
        "category": "auth-tokens",
    },
]

# Entropy-based detection threshold
HIGH_ENTROPY_THRESHOLD = 4.5


class SecretsScanner:
    """Detects hardcoded secrets and sensitive data in source code."""

    def __init__(self, config=None):
        self.config = config
        self.patterns = SECRET_PATTERNS
        self.findings: List[Dict[str, Any]] = []

    def _calculate_entropy(self, string: str) -> float:
        """Calculate Shannon entropy of a string.

        Args:
            string: Input string.

        Returns:
            Entropy value (higher = more random).
        """
        import math
        from collections import Counter

        if not string:
            return 0.0

        counts = Counter(string)
        length = len(string)
        entropy = 0.0

        for count in counts.values():
            probability = count / length
            if probability > 0:
                entropy -= probability * math.log2(probability)

        return entropy

    def scan_file(self, file_path: str, content: Optional[str] = None) -> List[Dict[str, Any]]:
        """Scan a single file for secrets.

        Args:
            file_path: Path to the file.
            content: Optional file content (will be read if not provided).

        Returns:
            List of secret findings.
        """
        from ..utils.helpers import read_file_safe

        if content is None:
            content = read_file_safe(file_path)
            if content is None:
                return []

        file_findings = []
        lines = content.split("\n")

        for pattern_info in self.patterns:
            try:
                for match in re.finditer(pattern_info["pattern"], content, re.IGNORECASE):
                    line_num = content[:match.start()].count("\n") + 1
                    line_content = lines[line_num - 1].strip() if line_num <= len(lines) else ""

                    # Check entropy for generic patterns to reduce false positives
                    matched_text = match.group(0)
                    if pattern_info["category"] == "generic-secrets":
                        entropy = self._calculate_entropy(matched_text)
                        if entropy < HIGH_ENTROPY_THRESHOLD:
                            continue

                    # Mask the secret in the snippet
                    masked_snippet = self._mask_secret(line_content)

                    finding = {
                        "id": f"SEC-{len(file_findings) + 1}",
                        "title": pattern_info["name"],
                        "description": f"Potential {pattern_info['name']} detected",
                        "severity": pattern_info["severity"],
                        "category": pattern_info["category"],
                        "file": file_path,
                        "line": line_num,
                        "code_snippet": masked_snippet[:200],
                        "remediation": "Move this secret to an environment variable or secrets manager. Never commit secrets to version control.",
                        "source": "SecretsScanner",
                        "agent": "SecretsScanner",
                        "confidence": 0.9,
                    }
                    file_findings.append(finding)
            except re.error:
                continue

        self.findings.extend(file_findings)
        logger.info(f"Secrets: Found {len(file_findings)} secrets in {file_path}")
        return file_findings

    def scan_directory(self, directory: str, excluded_dirs: Optional[List[str]] = None) -> List[Dict[str, Any]]:
        """Scan all files in a directory for secrets.

        Args:
            directory: Directory to scan.
            excluded_dirs: Directory names to exclude.

        Returns:
            List of all secret findings.
        """
        from ..utils.helpers import find_files

        if excluded_dirs is None:
            excluded_dirs = ["node_modules", ".git", "__pycache__", ".venv", "venv", "dist", "build"]

        # Scan all text file types
        extensions = [
            ".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".go", ".rb",
            ".php", ".c", ".cpp", ".cs", ".rs", ".swift", ".kt",
            ".html", ".css", ".json", ".yaml", ".yml", ".xml", ".ini",
            ".env", ".cfg", ".conf", ".toml", ".properties", ".sh", ".bash",
        ]

        files = find_files(directory, extensions=extensions, exclude_dirs=excluded_dirs)

        all_findings = []
        for file_path in files:
            findings = self.scan_file(file_path)
            all_findings.extend(findings)

        logger.info(f"Secrets: Scanned {len(files)} files, found {len(all_findings)} total secrets")
        return all_findings

    @staticmethod
    def _mask_secret(text: str) -> str:
        """Mask potential secrets in text for safe display.

        Args:
            text: Text containing a potential secret.

        Returns:
            Text with secret value masked.
        """
        # Mask values after = or : for common secret patterns
        masked = re.sub(
            r'(["\']?)([A-Za-z0-9/+=]{8,})(["\']?)',
            r'\1***MASKED***\3',
            text,
        )
        return masked

    def clear_findings(self):
        """Clear all findings."""
        self.findings = []
