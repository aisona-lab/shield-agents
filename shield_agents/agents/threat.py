"""Threat modeling agent for Shield Agents."""

import logging
from typing import Any, Dict, List, Optional

from .base import BaseAgent
from ..config import ShieldConfig
from ..llm import BaseLLMProvider, create_llm_provider

logger = logging.getLogger("shield_agents.threat_agent")


class ThreatAgent(BaseAgent):
    """Agent specialized in threat modeling and attack surface analysis.

    Identifies potential attack vectors, threat actors, and attack scenarios.
    """

    def __init__(self, config: ShieldConfig, llm: Optional[BaseLLMProvider] = None):
        super().__init__(config, llm)
        self.name = "ThreatAgent"

    def get_system_prompt(self) -> str:
        return (
            "You are a threat modeling expert. Analyze code from an attacker's perspective. "
            "Identify attack vectors, threat scenarios, and potential exploits. "
            "Map findings to MITRE ATT&CK techniques where applicable. "
            "Always respond with valid JSON containing a 'findings' array."
        )

    async def analyze(self, target: str, **kwargs) -> List[Dict[str, Any]]:
        """Analyze code for threat vectors.

        Args:
            target: Code content to analyze.
            **kwargs: Additional arguments (file_path).

        Returns:
            List of threat findings.
        """
        file_path = kwargs.get("file_path", "unknown")

        result = await self.llm.complete_json([
            {"role": "system", "content": self.get_system_prompt()},
            {"role": "user", "content": self._build_threat_prompt(target, file_path)},
        ])

        findings = result.get("findings", [])
        for finding in findings:
            finding["agent"] = self.name
            finding["source"] = self.name
            finding["file"] = file_path
            finding.setdefault("id", f"{self.name}-{len(self.findings) + 1}")
            finding.setdefault("severity", "MEDIUM")
            finding.setdefault("category", "threat")
            finding.setdefault("confidence", 0.7)
            self.add_finding(finding)

        logger.info(f"{self.name}: Found {len(findings)} threat vectors in {file_path}")
        return findings

    def _build_threat_prompt(self, code_content: str, file_path: str = "") -> str:
        return (
            f"Analyze the following code for potential attack vectors and threats.\n\n"
            f"File: {file_path}\n\n"
            f"```\n{code_content}\n```\n\n"
            f"Return JSON with 'findings' array. Each finding: title, description, severity, "
            f"attack_vector, mitre_technique, remediation."
        )
