"""Reconnaissance agent for Shield Agents."""

import logging
from typing import Any, Dict, List, Optional

from .base import BaseAgent
from ..config import ShieldConfig
from ..llm import BaseLLMProvider, create_llm_provider

logger = logging.getLogger("shield_agents.recon_agent")


class ReconAgent(BaseAgent):
    """Agent specialized in reconnaissance and information gathering.

    Identifies exposed information, debug endpoints, API keys, comments
    containing sensitive data, and other information disclosure issues.
    """

    def __init__(self, config: ShieldConfig, llm: Optional[BaseLLMProvider] = None):
        super().__init__(config, llm)
        self.name = "ReconAgent"

    def get_system_prompt(self) -> str:
        return (
            "You are a security reconnaissance expert. Analyze code for information disclosure, "
            "exposed debug endpoints, sensitive comments, metadata leaks, and other recon findings. "
            "Always respond with valid JSON containing a 'findings' array."
        )

    async def analyze(self, target: str, **kwargs) -> List[Dict[str, Any]]:
        """Analyze code for information disclosure.

        Args:
            target: Code content to analyze.
            **kwargs: Additional arguments (file_path).

        Returns:
            List of reconnaissance findings.
        """
        file_path = kwargs.get("file_path", "unknown")

        result = await self.llm.complete_json([
            {"role": "system", "content": self.get_system_prompt()},
            {"role": "user", "content": self._build_recon_prompt(target, file_path)},
        ])

        findings = result.get("findings", [])
        for finding in findings:
            finding["agent"] = self.name
            finding["source"] = self.name
            finding["file"] = file_path
            finding.setdefault("id", f"{self.name}-{len(self.findings) + 1}")
            finding.setdefault("severity", "LOW")
            finding.setdefault("category", "information-disclosure")
            finding.setdefault("confidence", 0.75)
            self.add_finding(finding)

        logger.info(f"{self.name}: Found {len(findings)} recon findings in {file_path}")
        return findings

    def _build_recon_prompt(self, code_content: str, file_path: str = "") -> str:
        return (
            f"Analyze the following code for information disclosure and recon findings.\n\n"
            f"File: {file_path}\n\n"
            f"```\n{code_content}\n```\n\n"
            f"Return JSON with 'findings' array. Each finding: title, description, severity, "
            f"category, line, code_snippet, remediation."
        )
