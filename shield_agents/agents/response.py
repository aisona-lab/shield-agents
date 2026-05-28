"""Incident response agent for Shield Agents."""

import logging
from typing import Any, Dict, List, Optional

from .base import BaseAgent
from ..config import ShieldConfig
from ..llm import BaseLLMProvider, create_llm_provider

logger = logging.getLogger("shield_agents.response_agent")


class ResponseAgent(BaseAgent):
    """Agent specialized in incident response and risk assessment.

    Provides risk scoring, incident response recommendations, and
    prioritized remediation guidance based on findings from other agents.
    """

    def __init__(self, config: ShieldConfig, llm: Optional[BaseLLMProvider] = None):
        super().__init__(config, llm)
        self.name = "ResponseAgent"

    def get_system_prompt(self) -> str:
        return (
            "You are an incident response expert. Analyze security findings and provide "
            "risk assessment, prioritized remediation plans, and incident response procedures. "
            "Focus on practical, actionable recommendations. "
            "Always respond with valid JSON."
        )

    async def analyze(self, target: str, **kwargs) -> List[Dict[str, Any]]:
        """Analyze findings and generate response recommendations.

        Args:
            target: JSON string of findings from other agents.
            **kwargs: Additional arguments.

        Returns:
            List of response/recommendation findings.
        """
        result = await self.llm.complete_json([
            {"role": "system", "content": self.get_system_prompt()},
            {"role": "user", "content": self._build_response_prompt(target)},
        ])

        findings = result.get("findings", result.get("recommendations", []))
        for finding in findings:
            finding["agent"] = self.name
            finding["source"] = self.name
            finding.setdefault("id", f"{self.name}-{len(self.findings) + 1}")
            finding.setdefault("severity", "MEDIUM")
            finding.setdefault("category", "incident-response")
            finding.setdefault("confidence", 0.85)
            self.add_finding(finding)

        logger.info(f"{self.name}: Generated {len(findings)} response recommendations")
        return findings

    def _build_response_prompt(self, findings_json: str) -> str:
        return (
            f"Based on the following security findings, provide risk assessment and "
            f"prioritized remediation recommendations:\n\n"
            f"{findings_json}\n\n"
            f"Return JSON with 'recommendations' array. Each: title, description, severity, "
            f"priority (1-5), action_steps (list), affected_findings (list of IDs)."
        )
