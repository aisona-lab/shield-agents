"""
SARIF (Static Analysis Results Interchange Format) Output for Shield Agents.

Generates SARIF 2.1.0 output for GitHub Security tab integration.
This is essential for GitHub integration - without it, you can't display
results in the GitHub Security tab.
"""

import json
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

logger = logging.getLogger("shield_agents.sarif")


class SARIFGenerator:
    """Generate SARIF 2.1.0 output from Shield Agents findings.

    SARIF is the standard format for static analysis results exchange.
    GitHub Security tab natively consumes SARIF files uploaded via
    the code-scanning API.
    """

    SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
    SARIF_VERSION = "2.1.0"

    # Map Shield Agents severity to SARIF level
    SEVERITY_MAP = {
        "CRITICAL": "error",
        "HIGH": "error",
        "MEDIUM": "warning",
        "LOW": "note",
        "INFO": "note",
    }

    def __init__(self, config=None):
        self.config = config

    def generate(self, findings: List[Dict[str, Any]], target_path: str = "") -> Dict[str, Any]:
        """Generate a SARIF report from findings.

        Args:
            findings: List of finding dictionaries.
            target_path: Root path of the scanned project.

        Returns:
            SARIF 2.1.0 compliant dictionary.
        """
        # Build rules from unique rule IDs
        rules, rule_indices = self._build_rules(findings)

        # Build results
        results = []
        for finding in findings:
            result = self._build_result(finding, rule_indices, target_path)
            results.append(result)

        sarif = {
            "$schema": self.SARIF_SCHEMA,
            "version": self.SARIF_VERSION,
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "Shield Agents",
                            "version": "2.0.0",
                            "semanticVersion": "2.0.0",
                            "informationUri": "https://github.com/shield-agents/shield-agents",
                            "rules": rules,
                            "organization": "Shield Agents",
                        }
                    },
                    "results": results,
                    "invocations": [
                        {
                            "executionSuccessful": True,
                            "startTimeUtc": datetime.now(timezone.utc).isoformat(),
                            "endTimeUtc": datetime.now(timezone.utc).isoformat(),
                        }
                    ],
                }
            ],
        }

        logger.info(f"Generated SARIF report with {len(results)} results and {len(rules)} rules")
        return sarif

    def generate_string(self, findings: List[Dict[str, Any]], target_path: str = "") -> str:
        """Generate SARIF report as JSON string.

        Args:
            findings: List of finding dictionaries.
            target_path: Root path of the scanned project.

        Returns:
            SARIF JSON string.
        """
        return json.dumps(self.generate(findings, target_path), indent=2)

    def save(self, findings: List[Dict[str, Any]], output_path: str, target_path: str = "") -> str:
        """Generate and save SARIF report to file.

        Args:
            findings: List of finding dictionaries.
            output_path: Path to save the SARIF file.
            target_path: Root path of the scanned project.

        Returns:
            Path to the saved file.
        """
        sarif = self.generate(findings, target_path)

        with open(output_path, "w") as f:
            json.dump(sarif, f, indent=2)

        logger.info(f"SARIF report saved to {output_path}")
        return output_path

    def _build_rules(self, findings: List[Dict[str, Any]]) -> tuple:
        """Build SARIF rules from findings.

        Args:
            findings: List of finding dictionaries.

        Returns:
            Tuple of (rules_list, rule_index_map).
        """
        seen_rules = {}
        rules = []
        rule_indices = {}

        for finding in findings:
            rule_id = finding.get("rule_id", finding.get("id", "unknown"))
            category = finding.get("category", "unknown")

            # Create a composite rule key
            rule_key = f"{rule_id}:{category}"

            if rule_key not in seen_rules:
                rule_index = len(rules)
                seen_rules[rule_key] = rule_index
                rule_indices[rule_key] = rule_index

                rule = {
                    "id": rule_id,
                    "name": finding.get("title", "Unknown"),
                    "shortDescription": {
                        "text": finding.get("title", "Unknown finding"),
                    },
                    "fullDescription": {
                        "text": finding.get("description", finding.get("title", "No description")),
                    },
                    "helpUri": f"https://cwe.mitre.org/data/definitions/{finding.get('cwe', '0').replace('CWE-', '')}.html" if finding.get("cwe") else "",
                    "properties": {
                        "category": category,
                        "severity": finding.get("severity", "MEDIUM"),
                    },
                }

                # Add remediation as help text
                if finding.get("remediation"):
                    rule["help"] = {
                        "text": finding["remediation"],
                    }

                rules.append(rule)

        return rules, rule_indices

    def _build_result(self, finding: Dict[str, Any], rule_indices: Dict[str, int], target_path: str = "") -> Dict[str, Any]:
        """Build a SARIF result entry from a finding.

        Args:
            finding: Finding dictionary.
            rule_indices: Map of rule keys to indices.
            target_path: Root path of the scanned project.

        Returns:
            SARIF result dictionary.
        """
        rule_id = finding.get("rule_id", finding.get("id", "unknown"))
        category = finding.get("category", "unknown")
        rule_key = f"{rule_id}:{category}"

        result = {
            "ruleId": rule_id,
            "ruleIndex": rule_indices.get(rule_key, 0),
            "level": self.SEVERITY_MAP.get(finding.get("severity", "MEDIUM").upper(), "warning"),
            "message": {
                "text": finding.get("description", finding.get("title", "No description")),
            },
        }

        # Add location if file info is available
        file_path = finding.get("file", "")
        if file_path:
            # Make path relative to target
            if target_path and file_path.startswith(target_path):
                file_path = file_path[len(target_path):].lstrip("/")

            location = {
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": file_path,
                    },
                },
            }

            # Add line number if available
            line = finding.get("line")
            if isinstance(line, int) and line > 0:
                location["physicalLocation"]["region"] = {
                    "startLine": line,
                }

            result["locations"] = [location]

        # Add code snippet as context region
        if finding.get("code_snippet"):
            if "locations" not in result:
                result["locations"] = [{}]
            if "physicalLocation" not in result["locations"][0]:
                result["locations"][0]["physicalLocation"] = {}
            result["locations"][0]["physicalLocation"]["contextRegion"] = {
                "snippet": {
                    "text": finding["code_snippet"],
                },
            }

        # Add additional properties
        result["properties"] = {}
        for key in ["agent", "source", "confidence", "cwe", "owasp", "remediation"]:
            if key in finding:
                result["properties"][key] = finding[key]

        if finding.get("sources"):
            result["properties"]["sources"] = finding["sources"]

        return result
