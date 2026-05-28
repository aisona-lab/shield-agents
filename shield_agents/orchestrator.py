"""
Orchestrator for Shield Agents.

Central coordinator that manages all agents, scanners, deduplication,
caching, and shieldignore filtering. Provides a unified interface for
running security scans.
"""

import asyncio
import json
import logging
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from .config import ShieldConfig
from .llm import create_llm_provider
from .agents import VulnAgent, ThreatAgent, ReconAgent, ComplianceAgent, ResponseAgent, AutoFixAgent
from .scanners import SASTScanner, SecretsScanner
from .deduplication import FindingDeduplicator
from .cache import ScanCache
from .shieldignore import ShieldIgnore
from .report import ReportGenerator
from .utils.helpers import find_files, read_file_safe, calculate_risk_score

logger = logging.getLogger("shield_agents.orchestrator")


class ScanResult:
    """Result of a security scan."""

    def __init__(self):
        self.findings: List[Dict[str, Any]] = []
        self.deduplicated_findings: List[Dict[str, Any]] = []
        self.filtered_findings: List[Dict[str, Any]] = []
        self.fixes: List[Dict[str, Any]] = []
        self.risk_score: int = 0
        self.scan_duration: float = 0.0
        self.files_scanned: int = 0
        self.stats: Dict[str, Any] = {}
        self.report_files: Dict[str, str] = {}

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "total_findings": len(self.filtered_findings),
            "risk_score": self.risk_score,
            "scan_duration": round(self.scan_duration, 2),
            "files_scanned": self.files_scanned,
            "findings": self.filtered_findings,
            "fixes": self.fixes,
            "stats": self.stats,
            "report_files": self.report_files,
        }


class Orchestrator:
    """Central orchestrator for Shield Agents security scans.

    Coordinates:
    - Static analysis (SAST + Secrets scanning)
    - AI agent analysis (Vuln, Threat, Recon, Compliance)
    - Auto-fix generation
    - Deduplication of findings
    - .shieldignore filtering
    - Caching / incremental scanning
    - Report generation (HTML, SARIF, JSON)
    """

    def __init__(self, config: Optional[ShieldConfig] = None):
        """Initialize the orchestrator.

        Args:
            config: Shield Agents configuration. Uses defaults if not provided.
        """
        self.config = config or ShieldConfig()

        # Initialize components
        self.llm = create_llm_provider(self.config.llm)
        self.sast_scanner = SASTScanner(self.config)
        self.secrets_scanner = SecretsScanner(self.config)
        self.deduplicator = FindingDeduplicator(
            similarity_threshold=self.config.deduplication.similarity_threshold,
            merge_sources=self.config.deduplication.merge_sources,
        )
        self.cache = ScanCache(
            cache_dir=self.config.cache.cache_dir,
            max_age_days=self.config.cache.max_cache_age_days,
        )
        self.shieldignore = ShieldIgnore(self.config.target_path)
        self.report_generator = ReportGenerator(self.config)

        # Initialize agents
        self.agents = {}
        if self.config.agents.vuln_agent:
            self.agents["vuln"] = VulnAgent(self.config, self.llm)
        if self.config.agents.threat_agent:
            self.agents["threat"] = ThreatAgent(self.config, self.llm)
        if self.config.agents.recon_agent:
            self.agents["recon"] = ReconAgent(self.config, self.llm)
        if self.config.agents.compliance_agent:
            self.agents["compliance"] = ComplianceAgent(self.config, self.llm)
        if self.config.agents.response_agent:
            self.agents["response"] = ResponseAgent(self.config, self.llm)
        if self.config.agents.autofix_agent:
            self.agents["autofix"] = AutoFixAgent(self.config, self.llm)

    async def scan(
        self,
        target_path: str,
        full_scan: bool = False,
        generate_report: bool = True,
        generate_fixes: bool = True,
    ) -> ScanResult:
        """Run a complete security scan.

        Args:
            target_path: Path to scan.
            full_scan: If True, ignore cache and scan all files.
            generate_report: If True, generate output reports.
            generate_fixes: If True, generate auto-fix suggestions.

        Returns:
            ScanResult with all findings and metadata.
        """
        start_time = time.time()
        result = ScanResult()

        # Update target path
        self.config.target_path = target_path

        # Load .shieldignore rules
        if self.config.shieldignore.enabled:
            self.shieldignore = ShieldIgnore(target_path)
            self.shieldignore.load()

        # Clean up expired cache entries
        if self.config.cache.enabled:
            self.cache.cleanup_expired()

        # Find source files to scan
        source_extensions = [
            ".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".go", ".rb",
            ".php", ".c", ".cpp", ".cs", ".rs", ".swift", ".kt",
            ".html", ".htm", ".xml", ".yaml", ".yml", ".json", ".sql",
            ".env", ".cfg", ".conf", ".toml", ".properties",
        ]

        # If target is a single file, scan it directly without directory traversal
        target_path_obj = Path(target_path).resolve()
        content_dirs_to_exclude = []  # Initialize for later reference

        if target_path_obj.is_file():
            all_files = [str(target_path_obj)]
        else:
            # Auto-exclude content dirs (tests, benchmarks, examples) only when they
            # are subdirectories - NOT when the user explicitly targets them
            target_name = target_path_obj.name

            content_dirs_to_exclude = [
                d for d in self.config.scanner.excluded_content_dirs
                if d != target_name  # Don't exclude the target itself
            ]

            excluded_dirs = (
                self.config.scanner.excluded_dirs +
                content_dirs_to_exclude
            )

            all_files = find_files(
                target_path,
                extensions=source_extensions,
                exclude_dirs=excluded_dirs,
            )

        # Filter by .shieldignore path rules
        if self.shieldignore.rules and self.shieldignore._loaded:
            filtered = []
            for fp in all_files:
                dummy_finding = {"file": fp, "title": "", "category": "", "severity": "MEDIUM"}
                if not self.shieldignore.should_ignore(dummy_finding):
                    filtered.append(fp)
            all_files = filtered

        # Filter out files in excluded content directories (tests, benchmarks, examples)
        # But only subdirectories, not the target itself
        if content_dirs_to_exclude:
            filtered_files = []
            for fp in all_files:
                parts = Path(fp).parts
                # Don't exclude if this is the target directory itself
                if not any(exc in parts for exc in content_dirs_to_exclude):
                    filtered_files.append(fp)
            all_files = filtered_files

        # Filter out excluded filenames
        if self.config.scanner.excluded_filenames:
            filtered_files = []
            for fp in all_files:
                filename = Path(fp).name
                if not any(filename.startswith(exc) or filename.endswith(exc) for exc in self.config.scanner.excluded_filenames):
                    filtered_files.append(fp)
            all_files = filtered_files

        # Determine which files need re-scanning (incremental)
        if self.config.cache.enabled and self.config.cache.incremental and not full_scan:
            changed_files = self.cache.get_changed_files(all_files)
            unchanged_files = self.cache.get_unchanged_files(all_files)

            logger.info(f"Incremental scan: {len(changed_files)} changed, {len(unchanged_files)} unchanged")

            # Get cached findings for unchanged files
            cached_findings = []
            for fp in unchanged_files:
                cached_findings.extend(self.cache.get_cached_findings(fp))

            files_to_scan = changed_files
        else:
            files_to_scan = all_files
            cached_findings = []

        result.files_scanned = len(files_to_scan)

        # Phase 1: Static analysis (SAST + Secrets)
        all_findings = list(cached_findings)

        # SAST scanning
        if self.config.scanner.sast_enabled:
            sast_findings = self._run_sast_scan(files_to_scan)
            all_findings.extend(sast_findings)

        # Secrets scanning
        if self.config.scanner.secrets_enabled:
            secrets_findings = self._run_secrets_scan(files_to_scan)
            all_findings.extend(secrets_findings)

        # Phase 2: AI agent analysis
        agent_findings = await self._run_agent_analysis(files_to_scan)
        all_findings.extend(agent_findings)

        # Phase 3: Deduplication
        if self.config.deduplication.enabled:
            result.deduplicated_findings = self.deduplicator.deduplicate(all_findings)
            result.stats["deduplication"] = self.deduplicator.get_stats()
        else:
            result.deduplicated_findings = all_findings

        # Phase 4: .shieldignore filtering
        if self.config.shieldignore.enabled:
            result.filtered_findings = self.shieldignore.filter_findings(result.deduplicated_findings)
            result.stats["shieldignore"] = self.shieldignore.get_stats()
        else:
            result.filtered_findings = result.deduplicated_findings

        # Phase 5: Auto-fix generation
        if generate_fixes and "autofix" in self.agents:
            findings_json = json.dumps(result.filtered_findings[:50])  # Limit for performance
            # Get code content for context
            code_content = self._gather_code_content(files_to_scan[:20])
            result.fixes = await self.agents["autofix"].analyze(
                findings_json, code_content=code_content
            )

        # Phase 6: Response agent (risk assessment and recommendations)
        if "response" in self.agents:
            response_findings = await self.agents["response"].analyze(
                json.dumps(result.filtered_findings[:30])
            )
            result.stats["response_recommendations"] = len(response_findings)

        # Calculate risk score
        result.risk_score = calculate_risk_score(result.filtered_findings)
        result.findings = all_findings

        # Update cache
        if self.config.cache.enabled:
            self._update_cache(files_to_scan, all_findings)
            self.cache.save()

        # Generate reports
        if generate_report:
            scan_stats = {
                "files_scanned": result.files_scanned,
                "total_files": len(all_files),
                "scan_duration": time.time() - start_time,
                "cache_enabled": self.config.cache.enabled,
                "dedup_enabled": self.config.deduplication.enabled,
                "shieldignore_enabled": self.config.shieldignore.enabled,
            }
            result.report_files = self.report_generator.generate_report(
                findings=result.filtered_findings,
                target_path=target_path,
                output_dir=self.config.report.output_dir,
                formats=self.config.report.formats,
                scan_stats=scan_stats,
            )

        result.scan_duration = time.time() - start_time
        result.stats["total_input_findings"] = len(all_findings)
        result.stats["after_dedup"] = len(result.deduplicated_findings)
        result.stats["after_filter"] = len(result.filtered_findings)

        logger.info(
            f"Scan complete: {len(all_findings)} findings → "
            f"{len(result.filtered_findings)} after dedup+filter, "
            f"risk score: {result.risk_score}/100, "
            f"duration: {result.scan_duration:.2f}s"
        )

        return result

    def _run_sast_scan(self, files: List[str]) -> List[Dict[str, Any]]:
        """Run SAST scanner on files."""
        all_findings = []
        for file_path in files:
            findings = self.sast_scanner.scan_file(file_path)
            all_findings.extend(findings)
        return all_findings

    def _run_secrets_scan(self, files: List[str]) -> List[Dict[str, Any]]:
        """Run Secrets scanner on files."""
        all_findings = []
        for file_path in files:
            findings = self.secrets_scanner.scan_file(file_path)
            all_findings.extend(findings)
        return all_findings

    async def _run_agent_analysis(self, files: List[str]) -> List[Dict[str, Any]]:
        """Run AI agent analysis on files."""
        all_findings = []
        
        # Limit the number of files sent to LLM for performance
        max_files_for_llm = 10
        files_for_llm = files[:max_files_for_llm]

        for file_path in files_for_llm:
            content = read_file_safe(file_path)
            if not content:
                continue

            # Run enabled agents concurrently for each file
            tasks = []
            for name, agent in self.agents.items():
                if name in ("response", "autofix"):
                    continue  # These run later with aggregated findings
                tasks.append(agent.analyze(content, file_path=file_path))

            if tasks:
                results = await asyncio.gather(*tasks, return_exceptions=True)
                for r in results:
                    if isinstance(r, list):
                        all_findings.extend(r)
                    elif isinstance(r, Exception):
                        logger.warning(f"Agent error: {r}")

        return all_findings

    def _gather_code_content(self, files: List[str], max_files: int = 20) -> str:
        """Gather code content from multiple files for context."""
        content_parts = []
        for fp in files[:max_files]:
            content = read_file_safe(fp)
            if content:
                # Truncate very long files
                if len(content) > 5000:
                    content = content[:5000] + "\n... (truncated)"
                content_parts.append(f"--- {fp} ---\n{content}\n")
        return "\n".join(content_parts)

    def _update_cache(self, files: List[str], findings: List[Dict[str, Any]]) -> None:
        """Update cache with scan results per file."""
        # Group findings by file
        findings_by_file: Dict[str, List[Dict[str, Any]]] = {}
        for f in findings:
            file_path = f.get("file", "")
            if file_path:
                findings_by_file.setdefault(file_path, []).append(f)

        # Update cache for each scanned file
        for file_path in files:
            file_findings = findings_by_file.get(file_path, [])
            self.cache.update_file(file_path, file_findings)
