"""Compliance checking agent for Shield Agents."""

import logging
from typing import Any, Dict, List, Optional

from .base import BaseAgent
from ..config import ShieldConfig
from ..llm import BaseLLMProvider, create_llm_provider
from ..knowledge.owasp import get_owasp_category

logger = logging.getLogger("shield_agents.compliance_agent")


class ComplianceAgent(BaseAgent):
    """Agent specialized in compliance and security standards checking.

    Checks code against OWASP Top 10, SANS Top 25, and other security standards.
    """

    def __init__(self, config: ShieldConfig, llm: Optional[BaseLLMProvider] = None):
        super().__init__(config, llm)
        self.name = "ComplianceAgent"

    def get_system_prompt(self) -> str:
        return (
            "You are a security compliance expert. Check code against OWASP Top 10 2021, "
            "SANS Top 25, and industry security standards. Identify compliance violations "
            "and provide specific standard references. "
            "Always respond with valid JSON containing a 'findings' array."
        )

    async def analyze(self, target: str, **kwargs) -> List[Dict[str, Any]]:
        """Analyze code for compliance violations.

        Args:
            target: Code content to analyze.
            **kwargs: Additional arguments (file_path).

        Returns:
            List of compliance findings.
        """
        file_path = kwargs.get("file_path", "unknown")

        result = await self.llm.complete_json([
            {"role": "system", "content": self.get_system_prompt()},
            {"role": "user", "content": self._build_compliance_prompt(target, file_path)},
        ])

        findings = result.get("findings", [])
        for finding in findings:
            finding["agent"] = self.name
            finding["source"] = self.name
            finding["file"] = file_path
            finding.setdefault("id", f"{self.name}-{len(self.findings) + 1}")
            finding.setdefault("severity", "MEDIUM")
            finding.setdefault("category", "compliance")
            finding.setdefault("confidence", 0.75)
            # Add OWASP mapping
            category = finding.get("category", "")
            owasp_info = get_owasp_category(category)
            finding["owasp"] = owasp_info.get("name", "Unknown")
            self.add_finding(finding)

        logger.info(f"{self.name}: Found {len(findings)} compliance issues in {file_path}")
        return findings

    def _build_compliance_prompt(self, code_content: str, file_path: str = "") -> str:
        return (
            f"Check the following code for compliance with OWASP Top 10 2021 and security standards.\n\n"
            f"File: {file_path}\n\n"
            f"```\n{code_content}\n```\n\n"
            f"Return JSON with 'findings' array. Each finding: title, description, severity, "
            f"category (use owasp category names), owasp_reference, line, remediation."
        )
