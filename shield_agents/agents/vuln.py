"""Vulnerability detection agent for Shield Agents."""

import logging
from typing import Any, Dict, List, Optional

from .base import BaseAgent
from ..config import ShieldConfig
from ..llm import BaseLLMProvider, create_llm_provider

logger = logging.getLogger("shield_agents.vuln_agent")


class VulnAgent(BaseAgent):
    """Agent specialized in detecting code vulnerabilities.

    Uses LLM analysis and pattern matching to identify security
    vulnerabilities like SQL injection, XSS, command injection, etc.
    """

    def __init__(self, config: ShieldConfig, llm: Optional[BaseLLMProvider] = None):
        super().__init__(config, llm)
        self.name = "VulnAgent"

    def get_system_prompt(self) -> str:
        return (
            "You are an expert security analyst specializing in vulnerability detection. "
            "Your task is to identify security vulnerabilities in code. "
            "Focus on: SQL injection, XSS, command injection, path traversal, "
            "insecure deserialization, authentication bypass, and other common vulnerabilities. "
            "For each finding, provide the severity, category, line number, and remediation advice. "
            "Always respond with valid JSON containing a 'findings' array."
        )

    async def analyze(self, target: str, **kwargs) -> List[Dict[str, Any]]:
        """Analyze code content for vulnerabilities.

        Args:
            target: Code content to analyze.
            **kwargs: Additional arguments (file_path).

        Returns:
            List of vulnerability findings.
        """
        file_path = kwargs.get("file_path", "unknown")

        if self.config.llm.provider == "mock":
            # Use smart mock provider which does pattern matching
            result = await self.llm.complete_json([
                {"role": "system", "content": self.get_system_prompt()},
                {"role": "user", "content": self._build_analysis_prompt(target, file_path)},
            ])
        else:
            # Use real LLM with fallback handling
            result = await self.llm.complete_json([
                {"role": "system", "content": self.get_system_prompt()},
                {"role": "user", "content": self._build_analysis_prompt(target, file_path)},
            ])

        findings = result.get("findings", [])
        for finding in findings:
            finding["agent"] = self.name
            finding["source"] = self.name
            finding["file"] = file_path
            finding.setdefault("id", f"{self.name}-{len(self.findings) + 1}")
            finding.setdefault("severity", "MEDIUM")
            finding.setdefault("category", "vulnerability")
            finding.setdefault("confidence", 0.8)
            self.add_finding(finding)

        logger.info(f"{self.name}: Found {len(findings)} vulnerabilities in {file_path}")
        return findings

    def _build_analysis_prompt(self, code_content: str, file_path: str = "") -> str:
        return (
            f"Analyze the following code for security vulnerabilities.\n\n"
            f"File: {file_path}\n\n"
            f"```\n{code_content}\n```\n\n"
            f"Return JSON with 'findings' array. Each finding: title, description, severity, "
            f"category, line, code_snippet, remediation, cwe."
        )
