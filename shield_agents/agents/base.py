"""Base agent class for all Shield Agents."""

import logging
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional

from ..config import ShieldConfig
from ..llm import BaseLLMProvider, create_llm_provider

logger = logging.getLogger("shield_agents.agents")


class BaseAgent(ABC):
    """Abstract base class for all security analysis agents.

    Each agent specializes in a particular aspect of security analysis
    and communicates findings through a standardized interface.
    """

    def __init__(self, config: ShieldConfig, llm: Optional[BaseLLMProvider] = None):
        self.config = config
        self.llm = llm or create_llm_provider(config.llm)
        self.name = self.__class__.__name__
        self.findings: List[Dict[str, Any]] = []

    @abstractmethod
    async def analyze(self, target: str, **kwargs) -> List[Dict[str, Any]]:
        """Analyze a target and return findings.

        Args:
            target: Path or content to analyze.
            **kwargs: Additional arguments.

        Returns:
            List of finding dictionaries.
        """
        pass

    @abstractmethod
    def get_system_prompt(self) -> str:
        """Return the system prompt for this agent's LLM interactions."""
        pass

    def add_finding(self, finding: Dict[str, Any]) -> None:
        """Add a finding to the agent's results.

        Args:
            finding: Finding dictionary with standardized fields.
        """
        # Ensure required fields
        finding.setdefault("id", f"{self.name}-{len(self.findings) + 1}")
        finding.setdefault("agent", self.name)
        finding.setdefault("severity", "MEDIUM")
        finding.setdefault("category", "unknown")
        finding.setdefault("source", self.name)
        finding.setdefault("confidence", 0.8)
        self.findings.append(finding)

    def clear_findings(self) -> None:
        """Clear all findings."""
        self.findings = []

    def get_findings(self) -> List[Dict[str, Any]]:
        """Get all findings."""
        return self.findings

    def _build_analysis_prompt(self, code_content: str, file_path: str = "") -> str:
        """Build a user prompt for LLM analysis.

        Args:
            code_content: Code to analyze.
            file_path: Path to the file being analyzed.

        Returns:
            Formatted prompt string.
        """
        return (
            f"Analyze the following code for security vulnerabilities.\n\n"
            f"File: {file_path or 'unknown'}\n\n"
            f"```\n{code_content}\n```\n\n"
            f"Return a JSON object with a 'findings' array. Each finding should have:\n"
            f"- title: Short description of the issue\n"
            f"- description: Detailed explanation\n"
            f"- severity: CRITICAL, HIGH, MEDIUM, LOW, or INFO\n"
            f"- category: Vulnerability category (e.g., injection, xss, auth)\n"
            f"- line: Line number where the issue was found\n"
            f"- code_snippet: The problematic code\n"
            f"- remediation: How to fix the issue\n"
            f"- cwe: CWE identifier if applicable\n"
        )
