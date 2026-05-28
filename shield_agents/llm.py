"""
LLM Provider abstraction for Shield Agents.

Supports multiple providers: OpenAI, Anthropic, Ollama, and a smart Mock provider.
Includes robust fallback parsing for invalid LLM JSON responses (~30% failure rate).
"""

import json
import re
import logging
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional

from .config import LLMConfig

logger = logging.getLogger("shield_agents.llm")


# =============================================================================
# FEATURE: Real LLM Fallback Handling
# Robust parsing for when LLMs return invalid JSON (~30% of the time)
# =============================================================================

class LLMResponseParser:
    """Parse LLM responses with multiple fallback strategies.

    Handles these common failure modes:
    1. Valid JSON - direct parse
    2. JSON wrapped in markdown code blocks (```json ... ```)
    3. JSON with trailing commas
    4. JSON with single quotes instead of double quotes
    5. JSON embedded in explanatory text
    6. Partial JSON that can be repaired
    7. Non-JSON structured text (bullet lists, etc.)
    """

    @staticmethod
    def parse(response_text: str) -> Dict[str, Any]:
        """Parse an LLM response with progressive fallback strategies.

        Args:
            response_text: Raw text response from the LLM.

        Returns:
            Parsed dictionary, or empty dict if all strategies fail.
        """
        if not response_text or not response_text.strip():
            return {}

        # Strategy 1: Direct JSON parse
        result = LLMResponseParser._try_direct_json(response_text)
        if result is not None:
            return result

        # Strategy 2: Extract from markdown code blocks
        result = LLMResponseParser._try_code_block_extraction(response_text)
        if result is not None:
            return result

        # Strategy 3: Fix common JSON issues
        result = LLMResponseParser._try_json_repair(response_text)
        if result is not None:
            return result

        # Strategy 4: Find JSON-like structure in text
        result = LLMResponseParser._try_embedded_json(response_text)
        if result is not None:
            return result

        # Strategy 5: Parse structured text into findings
        result = LLMResponseParser._try_text_to_structured(response_text)
        if result is not None:
            return result

        logger.warning("All LLM response parsing strategies failed")
        return {}

    @staticmethod
    def _try_direct_json(text: str) -> Optional[Dict]:
        """Strategy 1: Try direct JSON parsing."""
        try:
            result = json.loads(text.strip())
            if isinstance(result, dict):
                return result
            if isinstance(result, list) and len(result) > 0:
                return {"findings": result}
        except json.JSONDecodeError:
            pass
        return None

    @staticmethod
    def _try_code_block_extraction(text: str) -> Optional[Dict]:
        """Strategy 2: Extract JSON from markdown code blocks."""
        patterns = [
            r"```json\s*\n(.*?)\n\s*```",
            r"```\s*\n(.*?)\n\s*```",
            r"`(.*?)`",
        ]
        for pattern in patterns:
            matches = re.findall(pattern, text, re.DOTALL)
            for match in matches:
                try:
                    result = json.loads(match.strip())
                    if isinstance(result, dict):
                        return result
                    if isinstance(result, list):
                        return {"findings": result}
                except json.JSONDecodeError:
                    continue
        return None

    @staticmethod
    def _try_json_repair(text: str) -> Optional[Dict]:
        """Strategy 3: Fix common JSON issues and retry."""
        # Extract what looks like JSON content
        json_candidates = []

        # Try the whole text
        json_candidates.append(text.strip())

        # Try content between first { and last }
        brace_match = re.search(r'\{.*\}', text, re.DOTALL)
        if brace_match:
            json_candidates.append(brace_match.group(0))

        # Try content between first [ and last ]
        bracket_match = re.search(r'\[.*\]', text, re.DOTALL)
        if bracket_match:
            json_candidates.append(bracket_match.group(0))

        for candidate in json_candidates:
            repaired = candidate
            # Fix trailing commas before } or ]
            repaired = re.sub(r',\s*([}\]])', r'\1', repaired)
            # Fix single quotes to double quotes (careful with apostrophes)
            # Only replace single quotes that look like JSON delimiters
            repaired = re.sub(r"(?<![a-zA-Z])'([^']*?)'(?![a-zA-Z])", r'"\1"', repaired)
            # Fix unquoted keys
            repaired = re.sub(r'(\w+)\s*:', r'"\1":', repaired)
            # Fix double-quoted keys that got re-quoted
            repaired = re.sub(r'""(\w+)"":', r'"\1":', repaired)
            # Remove comments
            repaired = re.sub(r'//.*?\n', '\n', repaired)
            repaired = re.sub(r'/\*.*?\*/', '', repaired, flags=re.DOTALL)

            try:
                result = json.loads(repaired)
                if isinstance(result, dict):
                    return result
                if isinstance(result, list):
                    return {"findings": result}
            except json.JSONDecodeError:
                continue

        return None

    @staticmethod
    def _try_embedded_json(text: str) -> Optional[Dict]:
        """Strategy 4: Find JSON-like structure embedded in text."""
        # Look for patterns like "findings": [...] or "vulnerabilities": [...]
        patterns = [
            r'"findings"\s*:\s*(\[.*?\])',
            r'"vulnerabilities"\s*:\s*(\[.*?\])',
            r'"results"\s*:\s*(\[.*?\])',
            r'"issues"\s*:\s*(\[.*?\])',
        ]
        for pattern in patterns:
            match = re.search(pattern, text, re.DOTALL)
            if match:
                try:
                    findings = json.loads(match.group(1))
                    return {"findings": findings}
                except json.JSONDecodeError:
                    continue
        return None

    @staticmethod
    def _try_text_to_structured(text: str) -> Optional[Dict]:
        """Strategy 5: Parse structured text (bullet lists, numbered items) into findings."""
        findings = []

        # Match patterns like:
        # - **Vulnerability**: SQL Injection in login.py:42
        # - [HIGH] XSS vulnerability found in search.py
        # 1. SQL Injection - user input not sanitized
        bullet_patterns = [
            r'(?:^|\n)\s*[-*]\s*\**\s*(.+?)(?:\n|$)',
            r'(?:^|\n)\s*\d+\.\s*(.+?)(?:\n|$)',
            r'(?:^|\n)\s*\[(HIGH|MEDIUM|LOW|CRITICAL)\]\s*(.+?)(?:\n|$)',
        ]

        for pattern in bullet_patterns:
            matches = re.findall(pattern, text, re.MULTILINE)
            for match in matches:
                if isinstance(match, tuple):
                    severity = match[0] if match[0] in ("HIGH", "MEDIUM", "LOW", "CRITICAL") else "MEDIUM"
                    description = match[1] if len(match) > 1 else match[0]
                else:
                    severity = "MEDIUM"
                    description = match

                if len(description.strip()) > 5:
                    findings.append({
                        "title": description.strip()[:100],
                        "description": description.strip(),
                        "severity": severity,
                        "source": "llm_text_parse",
                    })

        if findings:
            return {"findings": findings}
        return None


# =============================================================================
# LLM Provider Base and Implementations
# =============================================================================

class BaseLLMProvider(ABC):
    """Abstract base class for LLM providers."""

    def __init__(self, config: LLMConfig):
        self.config = config

    @abstractmethod
    async def complete(self, messages: List[Dict[str, str]], **kwargs) -> str:
        """Send messages and return raw text response."""
        pass

    @abstractmethod
    async def complete_json(self, messages: List[Dict[str, str]], **kwargs) -> Dict[str, Any]:
        """Send messages and return parsed JSON response with fallback handling."""
        pass


class OpenAIProvider(BaseLLMProvider):
    """OpenAI API provider."""

    def __init__(self, config: LLMConfig):
        super().__init__(config)

    async def complete(self, messages: List[Dict[str, str]], **kwargs) -> str:
        try:
            import openai
            client = openai.AsyncOpenAI(
                api_key=self.config.api_key,
                base_url=self.config.base_url,
            )
            response = await client.chat.completions.create(
                model=self.config.model,
                messages=messages,
                temperature=self.config.temperature,
                max_tokens=self.config.max_tokens,
                timeout=self.config.timeout,
                **kwargs,
            )
            return response.choices[0].message.content or ""
        except ImportError:
            logger.error("openai package not installed. Run: pip install openai")
            return ""
        except Exception as e:
            logger.error(f"OpenAI API error: {e}")
            return ""

    async def complete_json(self, messages: List[Dict[str, str]], **kwargs) -> Dict[str, Any]:
        raw = await self.complete(messages, **kwargs)
        if not raw:
            return {}
        return LLMResponseParser.parse(raw)


class AnthropicProvider(BaseLLMProvider):
    """Anthropic API provider."""

    def __init__(self, config: LLMConfig):
        super().__init__(config)

    async def complete(self, messages: List[Dict[str, str]], **kwargs) -> str:
        try:
            import anthropic
            client = anthropic.AsyncAnthropic(api_key=self.config.api_key)
            # Extract system message if present
            system_msg = ""
            user_messages = []
            for msg in messages:
                if msg["role"] == "system":
                    system_msg = msg["content"]
                else:
                    user_messages.append(msg)

            response = await client.messages.create(
                model=self.config.model,
                max_tokens=self.config.max_tokens,
                system=system_msg,
                messages=user_messages,
                **kwargs,
            )
            return response.content[0].text if response.content else ""
        except ImportError:
            logger.error("anthropic package not installed. Run: pip install anthropic")
            return ""
        except Exception as e:
            logger.error(f"Anthropic API error: {e}")
            return ""

    async def complete_json(self, messages: List[Dict[str, str]], **kwargs) -> Dict[str, Any]:
        raw = await self.complete(messages, **kwargs)
        if not raw:
            return {}
        return LLMResponseParser.parse(raw)


class OllamaProvider(BaseLLMProvider):
    """Ollama local LLM provider."""

    def __init__(self, config: LLMConfig):
        super().__init__(config)
        if not self.config.base_url:
            self.config.base_url = "http://localhost:11434"

    async def complete(self, messages: List[Dict[str, str]], **kwargs) -> str:
        try:
            import httpx
            async with httpx.AsyncClient(timeout=self.config.timeout) as client:
                response = await client.post(
                    f"{self.config.base_url}/api/chat",
                    json={
                        "model": self.config.model,
                        "messages": messages,
                        "stream": False,
                        "options": {
                            "temperature": self.config.temperature,
                            "num_predict": self.config.max_tokens,
                        },
                    },
                )
                response.raise_for_status()
                data = response.json()
                return data.get("message", {}).get("content", "")
        except ImportError:
            logger.error("httpx package not installed. Run: pip install httpx")
            return ""
        except Exception as e:
            logger.error(f"Ollama API error: {e}")
            return ""

    async def complete_json(self, messages: List[Dict[str, str]], **kwargs) -> Dict[str, Any]:
        raw = await self.complete(messages, **kwargs)
        if not raw:
            return {}
        return LLMResponseParser.parse(raw)


# =============================================================================
# FEATURE: Smarter Mock Provider
# Pattern-matched findings based on actual code content, not static JSON
# =============================================================================

class MockProvider(BaseLLMProvider):
    """Smart Mock LLM provider that returns pattern-matched findings.

    Instead of returning static JSON, this provider analyzes the input code
    and returns findings that actually match the scanned content. This makes
    demo mode feel realistic and useful for testing.
    """

    # Pattern definitions: (regex_pattern, finding_info)
    VULNERABILITY_PATTERNS = [
        (r"execute\s*\(|exec\s*\(", {
            "title": "Dynamic Code Execution",
            "severity": "CRITICAL",
            "category": "injection",
            "description": "Use of exec/execute can lead to code injection if user input is involved",
            "remediation": "Avoid dynamic code execution. Use safe alternatives like ast.literal_eval() for parsing.",
            "cwe": "CWE-94",
        }),
        (r"eval\s*\(", {
            "title": "Unsafe eval() Usage",
            "severity": "CRITICAL",
            "category": "injection",
            "description": "eval() can execute arbitrary code if user input is passed",
            "remediation": "Replace eval() with ast.literal_eval() or specific parsing functions.",
            "cwe": "CWE-95",
        }),
        (r"SELECT\s+.*\s+FROM\s+.*\s+WHERE.*\+\s*[\w]+|f['\"].*SELECT.*WHERE|format\s*\(.*SELECT", {
            "title": "SQL Injection",
            "severity": "CRITICAL",
            "category": "injection",
            "description": "SQL query constructed with string formatting or concatenation",
            "remediation": "Use parameterized queries with placeholders instead of string formatting.",
            "cwe": "CWE-89",
        }),
        (r"cursor\.execute\s*\(\s*[f'\"]|\.raw\s*\(\s*[f'\"]", {
            "title": "SQL Injection via ORM Raw Query",
            "severity": "CRITICAL",
            "category": "injection",
            "description": "Raw SQL query with potential string interpolation",
            "remediation": "Use ORM query methods or parameterized raw queries.",
            "cwe": "CWE-89",
        }),
        (r"innerHTML\s*=|document\.write\s*\(", {
            "title": "Cross-Site Scripting (XSS)",
            "severity": "HIGH",
            "category": "xss",
            "description": "Direct DOM manipulation can lead to XSS if content is not sanitized",
            "remediation": "Use textContent instead of innerHTML, or sanitize with DOMPurify.",
            "cwe": "CWE-79",
        }),
        (r"os\.system\s*\(|subprocess\.call\s*\(|subprocess\.Popen\s*\(", {
            "title": "OS Command Injection",
            "severity": "CRITICAL",
            "category": "injection",
            "description": "OS command execution can lead to command injection",
            "remediation": "Use subprocess with shell=False and list arguments. Never pass user input to shell commands.",
            "cwe": "CWE-78",
        }),
        (r"pickle\.loads?\s*\(", {
            "title": "Unsafe Deserialization",
            "severity": "CRITICAL",
            "category": "deserialization",
            "description": "pickle can execute arbitrary code during deserialization",
            "remediation": "Use JSON or other safe serialization formats. If pickle is necessary, never deserialize untrusted data.",
            "cwe": "CWE-502",
        }),
        (r"yaml\.load\s*\([^)]*\)(?!.*Loader)", {
            "title": "Unsafe YAML Loading",
            "severity": "HIGH",
            "category": "deserialization",
            "description": "yaml.load() without safe Loader can execute arbitrary code",
            "remediation": "Use yaml.safe_load() or yaml.load(data, Loader=yaml.SafeLoader).",
            "cwe": "CWE-502",
        }),
        (r"hashlib\.(md5|sha1)\s*\(", {
            "title": "Weak Cryptographic Hash",
            "severity": "MEDIUM",
            "category": "cryptography",
            "description": "MD5 and SHA-1 are cryptographically broken and should not be used for security purposes",
            "remediation": "Use SHA-256 or stronger hashing algorithms.",
            "cwe": "CWE-328",
        }),
        (r"assert\s+", {
            "title": "Assertion Used in Security Context",
            "severity": "LOW",
            "category": "security-misconfiguration",
            "description": "Assertions can be disabled with -O flag and should not be used for security checks",
            "remediation": "Replace assertions with proper if/raise constructs for security validation.",
            "cwe": "CWE-617",
        }),
        (r"random\.(random|randint|choice)\s*\(", {
            "title": "Insecure Random Number Generator",
            "severity": "MEDIUM",
            "category": "cryptography",
            "description": "random module is not cryptographically secure",
            "remediation": "Use secrets module for security-sensitive random number generation.",
            "cwe": "CWE-338",
        }),
        (r"ssl\._create_unverified_context|verify\s*=\s*False|CERT_NONE", {
            "title": "SSL/TLS Verification Disabled",
            "severity": "HIGH",
            "category": "security-misconfiguration",
            "description": "SSL certificate verification is disabled",
            "remediation": "Always verify SSL certificates. Never use verify=False in production.",
            "cwe": "CWE-295",
        }),
        (r"jwt\.decode\s*\([^)]*\)(?!.*algorithms)", {
            "title": "JWT Algorithm Confusion",
            "severity": "HIGH",
            "category": "authentication",
            "description": "JWT decode without specifying algorithms can lead to algorithm confusion attacks",
            "remediation": "Always specify the expected algorithms parameter in jwt.decode().",
            "cwe": "CWE-327",
        }),
        (r"cors\s*=\s*True|Access-Control-Allow-Origin.*\*", {
            "title": "Overly Permissive CORS",
            "severity": "MEDIUM",
            "category": "security-misconfiguration",
            "description": "CORS is configured to allow all origins",
            "remediation": "Restrict CORS to specific trusted origins instead of using wildcard.",
            "cwe": "CWE-942",
        }),
        (r"render_template_string\s*\(", {
            "title": "Server-Side Template Injection (SSTI)",
            "severity": "CRITICAL",
            "category": "injection",
            "description": "render_template_string with user input can lead to SSTI",
            "remediation": "Never pass user input to template rendering. Use render_template with fixed templates.",
            "cwe": "CWE-1336",
        }),
        (r"\.format\s*\(|f['\"]", {
            "title": "Potential String Injection",
            "severity": "MEDIUM",
            "category": "injection",
            "description": "String formatting with potential user-controlled input",
            "remediation": "Validate and sanitize all user input before using in string formatting.",
            "cwe": "CWE-134",
        }),
    ]

    # Agent-specific patterns for differentiated demo mode
    # Each agent has its own perspective on the code
    AGENT_PATTERNS = {
        "VulnAgent": {
            "focus": "vulnerability detection",
            "extra_patterns": [
                (r'cursor\.execute\s*\(|\.raw\s*\(', {
                    "title": "SQL Injection Risk",
                    "severity": "CRITICAL",
                    "category": "injection",
                    "description": "Database query execution with potential SQL injection",
                    "remediation": "Use parameterized queries with placeholders",
                    "cwe": "CWE-89",
                }),
                (r'eval\s*\(|exec\s*\(', {
                    "title": "Dynamic Code Execution",
                    "severity": "CRITICAL",
                    "category": "injection",
                    "description": "Dynamic code execution can lead to code injection",
                    "remediation": "Avoid eval/exec, use safe alternatives",
                    "cwe": "CWE-94",
                }),
                (r'os\.system\s*\(|subprocess\.\w+\s*\(.*shell\s*=\s*True', {
                    "title": "OS Command Injection",
                    "severity": "CRITICAL",
                    "category": "injection",
                    "description": "OS command execution with potential injection",
                    "remediation": "Use subprocess with shell=False and list arguments",
                    "cwe": "CWE-78",
                }),
                (r'pickle\.loads?\s*\(', {
                    "title": "Insecure Deserialization",
                    "severity": "CRITICAL",
                    "category": "deserialization",
                    "description": "Pickle deserialization can execute arbitrary code",
                    "remediation": "Use JSON serialization or yaml.safe_load()",
                    "cwe": "CWE-502",
                }),
            ],
        },
        "ThreatAgent": {
            "focus": "threat modeling and attack vectors",
            "extra_patterns": [
                (r'request\.(args|form|data|json)', {
                    "title": "User Input Entry Point",
                    "severity": "MEDIUM",
                    "category": "attack-surface",
                    "description": "HTTP request parameter accepted without validation - potential attack vector",
                    "remediation": "Validate and sanitize all user input at entry points",
                    "mitre_technique": "T1190",
                }),
                (r'@app\.route', {
                    "title": "Exposed HTTP Endpoint",
                    "severity": "LOW",
                    "category": "attack-surface",
                    "description": "HTTP endpoint exposed to network - part of attack surface",
                    "remediation": "Ensure endpoints have proper authentication and rate limiting",
                    "mitre_technique": "T1190",
                }),
                (r'debug\s*=\s*True', {
                    "title": "Debug Mode Enabled",
                    "severity": "HIGH",
                    "category": "security-misconfiguration",
                    "description": "Debug mode enabled in application - exposes sensitive information",
                    "remediation": "Disable debug mode in production (debug=False)",
                    "mitre_technique": "T1078",
                }),
                (r'import\s+os|import\s+subprocess', {
                    "title": "System Module Import",
                    "severity": "LOW",
                    "category": "attack-surface",
                    "description": "System-level module imported - increases attack surface if misused",
                    "remediation": "Ensure system modules are used safely and inputs are validated",
                    "mitre_technique": "T1059",
                }),
            ],
        },
        "ReconAgent": {
            "focus": "reconnaissance and information disclosure",
            "extra_patterns": [
                (r'print\s*\(|logger\.\w+\s*\(', {
                    "title": "Information Leakage via Logging",
                    "severity": "LOW",
                    "category": "information-disclosure",
                    "description": "Print/logging statements may expose sensitive data in production logs",
                    "remediation": "Remove debug prints, use appropriate log levels, never log secrets",
                    "cwe": "CWE-532",
                }),
                (r'#\s*TODO|#\s*FIXME|#\s*HACK|#\s*XXX', {
                    "title": "Developer Comment - Potential Security Debt",
                    "severity": "INFO",
                    "category": "information-disclosure",
                    "description": "Developer comments indicate unfinished security work or known issues",
                    "remediation": "Review and resolve all security-related TODO/FIXME comments",
                }),
                (r'debug\s*=\s*True', {
                    "title": "Debug Information Exposure",
                    "severity": "HIGH",
                    "category": "information-disclosure",
                    "description": "Debug mode exposes stack traces and environment variables",
                    "remediation": "Set debug=False in production",
                    "cwe": "CWE-200",
                }),
                (r'secret|password|token|key', {
                    "title": "Security-Sensitive Variable Names",
                    "severity": "MEDIUM",
                    "category": "information-disclosure",
                    "description": "Variables with security-sensitive names may indicate secret handling",
                    "remediation": "Ensure secrets are loaded from environment, not hardcoded",
                    "cwe": "CWE-798",
                }),
            ],
        },
        "ComplianceAgent": {
            "focus": "OWASP compliance and security standards",
            "extra_patterns": [
                (r'cursor\.execute|\.raw\s*\(', {
                    "title": "OWASP A03:2021 - Injection Violation",
                    "severity": "CRITICAL",
                    "category": "compliance",
                    "description": "Raw database query execution violates OWASP A03:2021 Injection guidelines",
                    "remediation": "Use parameterized queries per OWASP A03:2021 recommendations",
                    "owasp": "A03:2021",
                    "cwe": "CWE-89",
                }),
                (r'verify\s*=\s*False|CERT_NONE|_create_unverified_context', {
                    "title": "OWASP A02:2021 - Cryptographic Failure",
                    "severity": "HIGH",
                    "category": "compliance",
                    "description": "SSL verification disabled violates OWASP A02:2021 Cryptographic Failures",
                    "remediation": "Enable certificate verification per OWASP A02:2021",
                    "owasp": "A02:2021",
                    "cwe": "CWE-295",
                }),
                (r'(?:password|api_key|secret)\s*=\s*["\'][^"\']+["\']', {
                    "title": "OWASP A07:2021 - Authentication Failure",
                    "severity": "HIGH",
                    "category": "compliance",
                    "description": "Hardcoded credentials violate OWASP A07:2021 Identification and Authentication Failures",
                    "remediation": "Use secrets management per OWASP A07:2021",
                    "owasp": "A07:2021",
                    "cwe": "CWE-798",
                }),
                (r'@app\.route.*methods', {
                    "title": "OWASP A01:2021 - Broken Access Control Review",
                    "severity": "MEDIUM",
                    "category": "compliance",
                    "description": "HTTP endpoint requires access control review per OWASP A01:2021",
                    "remediation": "Implement authentication and authorization on all endpoints",
                    "owasp": "A01:2021",
                }),
            ],
        },
    }

    def __init__(self, config: LLMConfig):
        super().__init__(config)
        self._pattern_cache = {}

    async def complete(self, messages: List[Dict[str, str]], **kwargs) -> str:
        """Analyze the code content in messages and return pattern-matched findings as JSON.
        
        Detects which agent is calling based on the system prompt and returns
        differentiated findings specific to that agent's specialty.
        """
        # Extract code content and detect calling agent
        code_content = ""
        calling_agent = None
        
        for msg in messages:
            content = msg.get("content", "")
            code_content += content + "\n"
            
            # Detect which agent is calling by examining system prompt
            if msg.get("role") == "system":
                content_lower = content.lower()
                for agent_name in self.AGENT_PATTERNS:
                    if agent_name.lower().replace("agent", "") in content_lower or agent_name.lower() in content_lower:
                        calling_agent = agent_name
                        break
                # Additional keyword-based detection
                if not calling_agent:
                    if "vulnerability" in content_lower and "detect" in content_lower:
                        calling_agent = "VulnAgent"
                    elif "threat" in content_lower and ("model" in content_lower or "attack" in content_lower):
                        calling_agent = "ThreatAgent"
                    elif "recon" in content_lower or "information disclosure" in content_lower:
                        calling_agent = "ReconAgent"
                    elif "compliance" in content_lower or "owasp" in content_lower:
                        calling_agent = "ComplianceAgent"

        # Get base findings from shared patterns
        findings = self._match_patterns(code_content)

        # Add agent-specific findings (these are DIFFERENT from SAST findings)
        if calling_agent and calling_agent in self.AGENT_PATTERNS:
            agent_info = self.AGENT_PATTERNS[calling_agent]
            for pattern_str, info in agent_info["extra_patterns"]:
                try:
                    for match in re.finditer(pattern_str, code_content, re.IGNORECASE | re.DOTALL):
                        line_num = code_content[:match.start()].count("\n") + 1
                        lines = code_content.split("\n")
                        line_content = lines[line_num - 1].strip() if line_num <= len(lines) else ""
                        
                        # Dedup by title+line within this agent
                        dedup_key = f"{info['title']}:{line_num}"
                        existing_keys = {f"{f['title']}:{f.get('line', 0)}" for f in findings}
                        if dedup_key in existing_keys:
                            continue
                            
                        finding = {
                            **info,
                            "line": line_num,
                            "code_snippet": line_content[:200],
                            "source": calling_agent,
                            "confidence": 0.75,
                        }
                        findings.append(finding)
                except re.error:
                    continue

        # Build a realistic LLM-like response
        result = {
            "findings": findings,
            "summary": f"Analysis complete. Found {len(findings)} potential security issues.",
            "confidence": 0.85 if findings else 0.95,
        }

        return json.dumps(result, indent=2)

    def _match_patterns(self, code: str) -> List[Dict[str, Any]]:
        """Match code against vulnerability patterns and return findings."""
        findings = []
        seen_titles = set()

        lines = code.split("\n")
        for pattern_info in self.VULNERABILITY_PATTERNS:
            pattern = pattern_info[0]
            info = pattern_info[1]

            try:
                for match in re.finditer(pattern, code, re.IGNORECASE | re.DOTALL):
                    # Find line number
                    line_num = code[:match.start()].count("\n") + 1
                    line_content = lines[line_num - 1].strip() if line_num <= len(lines) else ""

                    # Avoid duplicate findings of same type on adjacent lines
                    dedup_key = f"{info['title']}:{line_num}"
                    if dedup_key in seen_titles:
                        continue
                    seen_titles.add(dedup_key)

                    finding = {
                        **info,
                        "line": line_num,
                        "code_snippet": line_content[:200],
                        "source": "mock_provider",
                        "confidence": 0.8,
                    }
                    findings.append(finding)
            except re.error:
                continue

        return findings

    async def complete_json(self, messages: List[Dict[str, str]], **kwargs) -> Dict[str, Any]:
        """Return parsed JSON with fallback handling."""
        raw = await self.complete(messages, **kwargs)
        if not raw:
            return {}
        # Mock provider always returns valid JSON, but use parser for consistency
        return LLMResponseParser.parse(raw)


def create_llm_provider(config: LLMConfig) -> BaseLLMProvider:
    """Factory function to create the appropriate LLM provider.

    Args:
        config: LLM configuration.

    Returns:
        An instance of the appropriate LLM provider.
    """
    providers = {
        "mock": MockProvider,
        "openai": OpenAIProvider,
        "anthropic": AnthropicProvider,
        "ollama": OllamaProvider,
    }

    provider_class = providers.get(config.provider.lower())
    if provider_class is None:
        logger.warning(f"Unknown provider '{config.provider}', falling back to mock")
        provider_class = MockProvider

    return provider_class(config)
