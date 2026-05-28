"""
Configuration management for Shield Agents.

Supports YAML config files, environment variables, and sensible defaults.
"""

import os
import yaml
from dataclasses import dataclass, field
from typing import Dict, List, Optional
from pathlib import Path


@dataclass
class LLMConfig:
    """LLM provider configuration."""
    provider: str = "mock"  # mock, openai, anthropic, ollama
    api_key: Optional[str] = None
    model: str = "gpt-4"
    base_url: Optional[str] = None
    temperature: float = 0.1
    max_tokens: int = 4096
    timeout: int = 60
    max_retries: int = 3
    fallback_enabled: bool = True  # Enable robust fallback parsing


@dataclass
class ScannerConfig:
    """Scanner-specific configuration."""
    sast_enabled: bool = True
    secrets_enabled: bool = True
    dependency_enabled: bool = True
    max_file_size: int = 1024 * 1024  # 1MB
    excluded_extensions: List[str] = field(default_factory=lambda: [
        ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".svg",
        ".mp3", ".mp4", ".avi", ".mov", ".wav",
        ".zip", ".tar", ".gz", ".rar", ".7z",
        ".pdf", ".doc", ".docx", ".xls", ".xlsx",
        ".woff", ".woff2", ".ttf", ".eot",
    ])
    excluded_dirs: List[str] = field(default_factory=lambda: [
        "node_modules", ".git", "__pycache__", ".venv", "venv",
        "dist", "build", ".tox", ".mypy_cache", ".pytest_cache",
        "shield-cache", ".shield-cache", "shield-reports",
    ])
    excluded_content_dirs: List[str] = field(default_factory=lambda: [
        "tests", "test", "tests_", "__tests__",
        "benchmarks", "benchmark",
        "examples", "example", "examples_",
        "fixtures", "mocks",
    ])
    excluded_filenames: List[str] = field(default_factory=lambda: [
        "setup.py", "conftest.py",
    ])


@dataclass
class CacheConfig:
    """Caching and incremental scan configuration."""
    enabled: bool = True
    cache_dir: str = ".shield-cache"
    hash_algorithm: str = "sha256"
    max_cache_age_days: int = 30
    incremental: bool = True


@dataclass
class DeduplicationConfig:
    """Deduplication engine configuration."""
    enabled: bool = True
    similarity_threshold: float = 0.85
    merge_sources: bool = True


@dataclass
class SARIFConfig:
    """SARIF output configuration."""
    enabled: bool = True
    schema_uri: str = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
    version: str = "2.1.0"


@dataclass
class ShieldIgnoreConfig:
    """Shieldignore file configuration."""
    enabled: bool = True
    filename: str = ".shieldignore"


@dataclass
class AgentConfig:
    """Individual agent configuration."""
    vuln_agent: bool = True
    threat_agent: bool = True
    recon_agent: bool = True
    compliance_agent: bool = True
    response_agent: bool = True
    autofix_agent: bool = True


@dataclass
class ReportConfig:
    """Report generation configuration."""
    output_dir: str = "./shield-reports"
    formats: List[str] = field(default_factory=lambda: ["html", "sarif", "json"])
    include_remediation: bool = True
    include_code_snippets: bool = True


class ShieldConfig:
    """Main configuration class that aggregates all sub-configs."""

    def __init__(self, config_path: Optional[str] = None):
        self.llm = LLMConfig()
        self.scanner = ScannerConfig()
        self.cache = CacheConfig()
        self.deduplication = DeduplicationConfig()
        self.sarif = SARIFConfig()
        self.shieldignore = ShieldIgnoreConfig()
        self.agents = AgentConfig()
        self.report = ReportConfig()
        self.target_path: str = "."
        self.verbose: bool = False
        self.debug: bool = False

        # Load from environment variables first
        self._load_env()

        # Then override with config file if provided
        if config_path:
            self._load_yaml(config_path)

    def _load_env(self):
        """Load configuration from environment variables."""
        self.llm.provider = os.getenv("SHIELD_LLM_PROVIDER", self.llm.provider)
        self.llm.api_key = os.getenv("SHIELD_LLM_API_KEY", self.llm.api_key)
        self.llm.model = os.getenv("SHIELD_LLM_MODEL", self.llm.model)
        self.llm.base_url = os.getenv("SHIELD_LLM_BASE_URL", self.llm.base_url)

        if os.getenv("SHIELD_VERBOSE", "").lower() in ("1", "true", "yes"):
            self.verbose = True
        if os.getenv("SHIELD_DEBUG", "").lower() in ("1", "true", "yes"):
            self.debug = True

    def _load_yaml(self, config_path: str):
        """Load configuration from YAML file."""
        path = Path(config_path)
        if not path.exists():
            return

        with open(path, "r") as f:
            data = yaml.safe_load(f) or {}

        if "llm" in data:
            for k, v in data["llm"].items():
                if hasattr(self.llm, k):
                    setattr(self.llm, k, v)

        if "scanner" in data:
            for k, v in data["scanner"].items():
                if hasattr(self.scanner, k):
                    setattr(self.scanner, k, v)

        if "cache" in data:
            for k, v in data["cache"].items():
                if hasattr(self.cache, k):
                    setattr(self.cache, k, v)

        if "deduplication" in data:
            for k, v in data["deduplication"].items():
                if hasattr(self.deduplication, k):
                    setattr(self.deduplication, k, v)

        if "sarif" in data:
            for k, v in data["sarif"].items():
                if hasattr(self.sarif, k):
                    setattr(self.sarif, k, v)

        if "agents" in data:
            for k, v in data["agents"].items():
                if hasattr(self.agents, k):
                    setattr(self.agents, k, v)

        if "report" in data:
            for k, v in data["report"].items():
                if hasattr(self.report, k):
                    setattr(self.report, k, v)

        if "target_path" in data:
            self.target_path = data["target_path"]

    @classmethod
    def from_file(cls, config_path: str) -> "ShieldConfig":
        """Create configuration from a YAML file."""
        return cls(config_path=config_path)

    def to_dict(self) -> dict:
        """Export configuration as dictionary."""
        import dataclasses
        result = {}
        for attr_name in ["llm", "scanner", "cache", "deduplication", "sarif", "shieldignore", "agents", "report"]:
            attr = getattr(self, attr_name)
            if dataclasses.is_dataclass(attr):
                result[attr_name] = dataclasses.asdict(attr)
        result["target_path"] = self.target_path
        result["verbose"] = self.verbose
        result["debug"] = self.debug
        return result
