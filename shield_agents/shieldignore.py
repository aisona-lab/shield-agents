"""
.shieldignore file support for Shield Agents.

Like .gitignore but for suppressing false positives.
Users can specify patterns to exclude specific findings from reports.
Without this, users get annoyed quickly by false positives.
"""

import logging
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

logger = logging.getLogger("shield_agents.shieldignore")


class ShieldIgnore:
    """Parse and apply .shieldignore rules to filter findings.

    The .shieldignore file supports these rule types:
    - file:path/to/file.py          # Ignore all findings in a specific file
    - rule:SAST-001                 # Ignore a specific rule
    - category:sql_injection        # Ignore all findings of a category
    - severity:LOW                  # Ignore all findings below a severity
    - id:VulnAgent-3                # Ignore a specific finding by ID
    - path:*.test.*                 # Ignore findings in files matching pattern
    - line:42:path/to/file.py       # Ignore finding at specific line in file
    - title:Assertion*              # Ignore findings with matching title (glob)
    """

    def __init__(self, target_path: str = "."):
        """Initialize ShieldIgnore.

        Args:
            target_path: Root path to search for .shieldignore file.
        """
        self.target_path = Path(target_path)
        self.rules: List[Dict[str, Any]] = []
        self._loaded = False
        self._stats = {
            "rules_loaded": 0,
            "findings_filtered": 0,
        }

    def load(self, ignore_path: Optional[str] = None) -> None:
        """Load .shieldignore rules from file.

        Args:
            ignore_path: Path to the ignore file. Defaults to .shieldignore in target_path.
        """
        if ignore_path:
            path = Path(ignore_path)
        else:
            path = self.target_path / ".shieldignore"

        if not path.exists():
            logger.debug(f"No .shieldignore file found at {path}")
            return

        try:
            with open(path, "r") as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    # Skip empty lines and comments
                    if not line or line.startswith("#"):
                        continue

                    rule = self._parse_rule(line, line_num)
                    if rule:
                        self.rules.append(rule)

            self._stats["rules_loaded"] = len(self.rules)
            logger.info(f"Loaded {len(self.rules)} .shieldignore rules from {path}")
            self._loaded = True
        except IOError as e:
            logger.warning(f"Failed to read .shieldignore: {e}")

    def _parse_rule(self, line: str, line_num: int) -> Optional[Dict[str, Any]]:
        """Parse a single .shieldignore rule.

        Args:
            line: Rule text.
            line_num: Line number in the file.

        Returns:
            Parsed rule dictionary, or None if invalid.
        """
        # Support both "type:value" and plain glob patterns
        if ":" in line:
            parts = line.split(":", 1)
            rule_type = parts[0].strip().lower()
            rule_value = parts[1].strip()
        else:
            # Plain pattern is treated as a file/path glob
            rule_type = "path"
            rule_value = line

        valid_types = {"file", "rule", "category", "severity", "id", "path", "line", "title", "cwe"}

        if rule_type not in valid_types:
            logger.warning(f"Invalid .shieldignore rule type '{rule_type}' at line {line_num}")
            return None

        # Compile glob patterns
        compiled_pattern = None
        if rule_type in ("path", "title"):
            # Convert glob to regex
            pattern = re.escape(rule_value)
            pattern = pattern.replace(r"\*", ".*").replace(r"\?", ".")
            try:
                compiled_pattern = re.compile(f"^{pattern}$", re.IGNORECASE)
            except re.error:
                logger.warning(f"Invalid pattern '{rule_value}' at line {line_num}")
                return None

        rule = {
            "type": rule_type,
            "value": rule_value,
            "pattern": compiled_pattern,
            "line_num": line_num,
        }

        # Parse compound rules like "line:42:path/to/file.py"
        if rule_type == "line" and ":" in rule_value:
            sub_parts = rule_value.split(":", 1)
            try:
                rule["line_number"] = int(sub_parts[0])
                rule["file_path"] = sub_parts[1]
            except (ValueError, IndexError):
                logger.warning(f"Invalid line rule '{rule_value}' at line {line_num}")
                return None

        return rule

    def should_ignore(self, finding: Dict[str, Any]) -> bool:
        """Check if a finding should be ignored based on .shieldignore rules.

        Args:
            finding: Finding dictionary.

        Returns:
            True if the finding should be suppressed.
        """
        if not self._loaded:
            self.load()

        for rule in self.rules:
            if self._matches_rule(finding, rule):
                self._stats["findings_filtered"] += 1
                return True

        return False

    def _matches_rule(self, finding: Dict[str, Any], rule: Dict[str, Any]) -> bool:
        """Check if a finding matches a specific ignore rule.

        Args:
            finding: Finding dictionary.
            rule: Ignore rule dictionary.

        Returns:
            True if the finding matches the rule.
        """
        rule_type = rule["type"]
        rule_value = rule["value"]

        if rule_type == "file":
            # Match file path
            finding_file = finding.get("file", "")
            return finding_file == rule_value or finding_file.endswith(rule_value)

        elif rule_type == "rule":
            # Match rule ID
            finding_rule = finding.get("rule_id", "")
            return finding_rule == rule_value

        elif rule_type == "category":
            # Match category
            finding_cat = finding.get("category", "").lower()
            return finding_cat == rule_value.lower()

        elif rule_type == "severity":
            # Ignore findings at or below this severity
            severity_order = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
            finding_sev = severity_order.get(finding.get("severity", "MEDIUM").upper(), 2)
            rule_sev = severity_order.get(rule_value.upper(), 2)
            return finding_sev <= rule_sev

        elif rule_type == "id":
            # Match exact finding ID
            return finding.get("id", "") == rule_value

        elif rule_type == "path":
            # Match file path pattern (glob)
            finding_file = finding.get("file", "")
            pattern = rule.get("pattern")
            if pattern is not None:
                try:
                    return bool(pattern.match(finding_file))
                except (TypeError, AttributeError):
                    return False
            return False

        elif rule_type == "line":
            # Match specific line in specific file
            if "line_number" in rule and "file_path" in rule:
                return (finding.get("line") == rule["line_number"] and
                        finding.get("file", "").endswith(rule["file_path"]))
            return False

        elif rule_type == "title":
            # Match title pattern (glob)
            finding_title = finding.get("title", "")
            pattern = rule.get("pattern")
            if pattern:
                return bool(pattern.match(finding_title))
            return False

        elif rule_type == "cwe":
            # Match CWE identifier
            return finding.get("cwe", "") == rule_value

        return False

    def filter_findings(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Filter a list of findings, removing those matching ignore rules.

        Args:
            findings: List of finding dictionaries.

        Returns:
            Filtered list of findings.
        """
        if not self._loaded:
            self.load()

        if not self.rules:
            return findings

        filtered = []
        for finding in findings:
            if not self.should_ignore(finding):
                filtered.append(finding)
            else:
                logger.debug(f"Suppressed finding: {finding.get('title', 'unknown')}")

        removed = len(findings) - len(filtered)
        if removed > 0:
            logger.info(f".shieldignore: Suppressed {removed} findings")

        return filtered

    def get_stats(self) -> Dict[str, int]:
        """Get filtering statistics.

        Returns:
            Dictionary of filtering statistics.
        """
        return self._stats.copy()

    @staticmethod
    def create_template(path: str = ".") -> str:
        """Create a template .shieldignore file.

        Args:
            path: Directory to create the file in.

        Returns:
            Path to the created file.
        """
        template = """# Shield Agents Ignore File
# Like .gitignore but for suppressing false positives
#
# Rule types:
#   file:path/to/file.py          - Ignore all findings in a file
#   rule:SAST-001                 - Ignore a specific rule ID
#   category:sql_injection        - Ignore all findings of a category
#   severity:LOW                  - Ignore findings at or below severity
#   id:VulnAgent-3                - Ignore a specific finding by ID
#   path:*.test.*                 - Ignore findings in matching file paths
#   line:42:path/to/file.py       - Ignore finding at specific line
#   title:Assertion*              - Ignore findings with matching title
#   cwe:CWE-617                   - Ignore findings with matching CWE

# Common suppressions for test files
path:*test*
path:*spec*
path:*__pycache__*

# Common low-severity suppressions
# severity:LOW
# category:information-disclosure
"""
        dir_path = Path(path)
        dir_path.mkdir(parents=True, exist_ok=True)
        file_path = dir_path / ".shieldignore"
        file_path.write_text(template)
        return str(file_path)
