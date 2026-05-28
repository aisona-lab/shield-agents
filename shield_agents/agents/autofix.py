"""Auto-fix / remediation agent for Shield Agents - The Master White Hat Hacker."""

import logging
import re
from typing import Any, Dict, List, Optional

from .base import BaseAgent
from ..config import ShieldConfig
from ..llm import BaseLLMProvider, create_llm_provider

logger = logging.getLogger("shield_agents.autofix_agent")


class AutoFixAgent(BaseAgent):
    """The Master White Hat Hacker agent that automatically fixes vulnerabilities.

    Analyzes findings from other agents and generates:
    1. Specific code fixes for each vulnerability
    2. Patch files that can be applied directly
    3. Step-by-step remediation plans
    4. Security hardening recommendations

    This agent is the crown jewel - it doesn't just find problems, it fixes them.
    """

    # Built-in fix patterns for common vulnerabilities
    FIX_PATTERNS = {
        "sql_injection": {
            "pattern": r'(cursor\.execute|\.raw)\s*\(\s*[f"\'](.*?)(?:["\']\s*\.format|\+) ',
            "fix_template": "Use parameterized query: cursor.execute(\"SELECT ... WHERE id = %s\", (user_id,))",
            "language": "python",
        },
        "eval_usage": {
            "pattern": r'eval\s*\(',
            "fix_template": "Replace eval() with ast.literal_eval() for safe evaluation of literals",
            "language": "python",
        },
        "pickle_usage": {
            "pattern": r'pickle\.loads?\s*\(',
            "fix_template": "Replace pickle with JSON serialization or use pickle only with trusted data",
            "language": "python",
        },
        "hardcoded_secret": {
            "pattern": r'(password|secret|api_key|token)\s*=\s*["\'][^"\']+["\']',
            "fix_template": "Move secrets to environment variables: os.environ.get('SECRET_KEY')",
            "language": "python",
        },
        "ssl_verification": {
            "pattern": r'verify\s*=\s*False|CERT_NONE|_create_unverified_context',
            "fix_template": "Enable SSL verification: remove verify=False or use default SSL context",
            "language": "python",
        },
        "weak_hash": {
            "pattern": r'hashlib\.(md5|sha1)\s*\(',
            "fix_template": "Replace with stronger hash: hashlib.sha256() or hashlib.sha512()",
            "language": "python",
        },
        "unsafe_yaml": {
            "pattern": r'yaml\.load\s*\([^)]*\)(?!.*Loader)',
            "fix_template": "Use safe YAML loading: yaml.safe_load() or yaml.load(data, Loader=yaml.SafeLoader)",
            "language": "python",
        },
        "command_injection": {
            "pattern": r'os\.system\s*\(|subprocess\.\w+\s*\([^)]*shell\s*=\s*True',
            "fix_template": "Use subprocess with shell=False and pass arguments as a list",
            "language": "python",
        },
        "xss_dom": {
            "pattern": r'innerHTML\s*=|document\.write\s*\(',
            "fix_template": "Use textContent instead of innerHTML, or sanitize with DOMPurify",
            "language": "javascript",
        },
        "cors_wildcard": {
            "pattern": r'Access-Control-Allow-Origin.*\*|cors\s*=\s*True',
            "fix_template": "Restrict CORS to specific origins: Access-Control-Allow-Origin: https://trusted-domain.com",
            "language": "python",
        },
    }

    def __init__(self, config: ShieldConfig, llm: Optional[BaseLLMProvider] = None):
        super().__init__(config, llm)
        self.name = "AutoFixAgent"

    def get_system_prompt(self) -> str:
        return (
            "You are a master white hat hacker and security remediation expert. "
            "Given security findings, you produce specific, copy-paste-ready code fixes. "
            "For each finding, provide: the exact code change needed, an explanation of why "
            "the fix works, and any additional hardening steps. "
            "Always respond with valid JSON."
        )

    async def analyze(self, target: str, **kwargs) -> List[Dict[str, Any]]:
        """Generate fixes for security findings.

        Args:
            target: JSON string of findings from other agents.
            **kwargs: Additional arguments (code_content for context).

        Returns:
            List of fix/remediation findings.
        """
        code_content = kwargs.get("code_content", "")

        # First try pattern-based fixes (instant, no LLM needed)
        pattern_fixes = self._generate_pattern_fixes(target, code_content)

        # Then get LLM-powered analysis for deeper fixes
        llm_fixes = []
        if self.config.llm.provider != "mock" or pattern_fixes == []:
            result = await self.llm.complete_json([
                {"role": "system", "content": self.get_system_prompt()},
                {"role": "user", "content": self._build_fix_prompt(target, code_content)},
            ])
            llm_fixes = result.get("findings", result.get("fixes", []))

        all_fixes = pattern_fixes + llm_fixes
        for fix in all_fixes:
            fix["agent"] = self.name
            fix["source"] = self.name
            fix.setdefault("id", f"{self.name}-{len(self.findings) + 1}")
            fix.setdefault("severity", "INFO")
            fix.setdefault("category", "remediation")
            fix.setdefault("confidence", 0.9)
            self.add_finding(fix)

        logger.info(f"{self.name}: Generated {len(all_fixes)} fixes/remediations")
        return all_fixes

    def _generate_pattern_fixes(self, findings_json: str, code_content: str) -> List[Dict[str, Any]]:
        """Generate fixes using built-in patterns - instant, no LLM needed."""
        fixes = []

        for vuln_type, fix_info in self.FIX_PATTERNS.items():
            try:
                matches = list(re.finditer(fix_info["pattern"], code_content, re.IGNORECASE))
                for match in matches:
                    line_num = code_content[:match.start()].count("\n") + 1
                    fixes.append({
                        "title": f"Auto-fix: {vuln_type.replace('_', ' ').title()}",
                        "description": f"Automatically detected and generated fix for {vuln_type.replace('_', ' ')}",
                        "vulnerability_type": vuln_type,
                        "line": line_num,
                        "code_snippet": match.group(0),
                        "fix": fix_info["fix_template"],
                        "language": fix_info["language"],
                        "fix_type": "pattern_based",
                        "auto_applicable": True,
                        "severity": "INFO",
                    })
            except re.error:
                continue

        return fixes

    def _build_fix_prompt(self, findings_json: str, code_content: str = "") -> str:
        prompt = (
            f"Given these security findings:\n\n{findings_json}\n\n"
        )
        if code_content:
            prompt += f"And the following source code:\n\n```\n{code_content}\n```\n\n"
        prompt += (
            "Generate specific, copy-paste-ready code fixes for each finding. "
            "Return JSON with 'fixes' array. Each fix: title, description, "
            "vulnerability_type, original_code, fixed_code, explanation, severity."
        )
        return prompt
