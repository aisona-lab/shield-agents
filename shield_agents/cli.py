"""
Command-line interface for Shield Agents.

Provides a beautiful, interactive CLI using the Rich library for
progress bars, tables, and colored output.
"""

import argparse
import asyncio
import json
import logging
import sys
from pathlib import Path
from typing import Optional

from . import __version__
from .config import ShieldConfig
from .orchestrator import Orchestrator
from .shieldignore import ShieldIgnore
from .cache import ScanCache

logger = logging.getLogger("shield_agents.cli")


def setup_logging(verbose: bool = False, debug: bool = False):
    """Configure logging based on verbosity."""
    level = logging.DEBUG if debug else (logging.INFO if verbose else logging.WARNING)
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )


def create_parser() -> argparse.ArgumentParser:
    """Create the CLI argument parser."""
    parser = argparse.ArgumentParser(
        prog="shield-agents",
        description="Shield Agents - AI-Powered Multi-Agent Cybersecurity Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  shield-agents scan ./my-project              # Scan a project
  shield-agents scan ./my-project --full        # Full scan (ignore cache)
  shield-agents scan ./my-project --fix         # Scan with auto-fix suggestions
  shield-agents scan ./my-project --sarif-only  # Output only SARIF for GitHub
  shield-agents init                            # Create .shieldignore template
  shield-agents cache --clear                   # Clear scan cache
  shield-agents cache --stats                   # Show cache statistics
  shield-agents version                         # Show version info
        """,
    )

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # Scan command
    scan_parser = subparsers.add_parser("scan", help="Run security scan")
    scan_parser.add_argument("target", help="Path to scan")
    scan_parser.add_argument("--config", "-c", help="Path to config YAML file")
    scan_parser.add_argument("--full", action="store_true", help="Full scan (ignore cache)")
    scan_parser.add_argument("--fix", action="store_true", help="Generate auto-fix suggestions")
    scan_parser.add_argument("--no-report", action="store_true", help="Skip report generation")
    scan_parser.add_argument("--sarif-only", action="store_true", help="Output only SARIF format")
    scan_parser.add_argument("--output", "-o", help="Output directory for reports")
    scan_parser.add_argument("--provider", choices=["mock", "openai", "anthropic", "ollama"], help="LLM provider")
    scan_parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    scan_parser.add_argument("--debug", action="store_true", help="Debug output")
    scan_parser.add_argument("--no-cache", action="store_true", help="Disable caching")
    scan_parser.add_argument("--no-dedup", action="store_true", help="Disable deduplication")
    scan_parser.add_argument("--no-ignore", action="store_true", help="Ignore .shieldignore rules")
    scan_parser.add_argument("--ci", action="store_true", help="CI/CD mode: SARIF output, JSON to stdout, silent except errors")
    scan_parser.add_argument("--format", "-f", choices=["rich", "json", "sarif", "plain"], default="rich", help="Output format (default: rich)")
    scan_parser.add_argument("--fail-threshold", type=int, default=75, help="Risk score threshold for CI failure (default: 75)")

    # Init command
    init_parser = subparsers.add_parser("init", help="Initialize Shield Agents configuration")
    init_parser.add_argument("--path", default=".", help="Directory to initialize")

    # Cache command
    cache_parser = subparsers.add_parser("cache", help="Manage scan cache")
    cache_parser.add_argument("--clear", action="store_true", help="Clear the cache")
    cache_parser.add_argument("--stats", action="store_true", help="Show cache statistics")

    # Version command
    subparsers.add_parser("version", help="Show version information")

    return parser


async def run_scan_ci(args) -> int:
    """CI/CD optimized scan - silent except for JSON output on stdout."""
    config = ShieldConfig(config_path=args.config) if args.config else ShieldConfig()
    config.target_path = args.target

    # Apply CLI overrides
    if args.provider:
        config.llm.provider = args.provider
    if args.output:
        config.report.output_dir = args.output
    if args.no_cache:
        config.cache.enabled = False
    if args.no_dedup:
        config.deduplication.enabled = False

    # CI mode: always generate SARIF + JSON (or SARIF only if --sarif-only)
    config.report.formats = ["sarif", "json"] if not getattr(args, 'sarif_only', False) else ["sarif"]

    # Minimal logging for CI
    setup_logging(verbose=False, debug=False)

    orchestrator = Orchestrator(config)
    result = await orchestrator.scan(
        target_path=args.target,
        full_scan=args.full,
        generate_report=True,
        generate_fixes=args.fix,
    )

    # Output JSON to stdout for CI pipeline consumption
    output = result.to_dict()
    print(json.dumps(output, indent=2))

    # Exit code based on risk threshold
    threshold = getattr(args, 'fail_threshold', 75) or 75
    return 1 if result.risk_score >= threshold else 0


async def run_scan(args) -> int:
    """Execute the scan command."""
    # If format is json, use CI-style output
    if getattr(args, 'format', 'rich') == 'json':
        return await run_scan_ci(args)

    try:
        from rich.console import Console
        from rich.progress import Progress, SpinnerColumn, TextColumn
        from rich.table import Table
        from rich.panel import Panel
        from rich import box
    except ImportError:
        # Fallback without Rich
        return await _run_scan_simple(args)

    console = Console()

    # Load configuration
    config = ShieldConfig(config_path=args.config) if args.config else ShieldConfig()
    config.target_path = args.target

    # Apply CLI overrides
    if args.provider:
        config.llm.provider = args.provider
    if args.output:
        config.report.output_dir = args.output
    if args.no_cache:
        config.cache.enabled = False
    if args.no_dedup:
        config.deduplication.enabled = False
    if args.no_ignore:
        config.shieldignore.enabled = False
    if args.sarif_only:
        config.report.formats = ["sarif"]
    if args.ci:
        config.report.formats = ["sarif", "json"]

    config.verbose = args.verbose
    config.debug = args.debug
    setup_logging(args.verbose, args.debug)

    # Display header
    console.print(Panel.fit(
        "[bold blue]Shield Agents[/bold blue] - AI-Powered Security Scanner\n"
        f"[dim]Version {__version__} | Provider: {config.llm.provider}[/dim]",
        border_style="blue",
    ))

    # Run scan
    orchestrator = Orchestrator(config)

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Scanning...", total=None)
        result = await orchestrator.scan(
            target_path=args.target,
            full_scan=args.full,
            generate_report=not args.no_report,
            generate_fixes=args.fix,
        )
        progress.update(task, completed=True)

    # Display results
    severity_colors = {
        "CRITICAL": "bold red",
        "HIGH": "red",
        "MEDIUM": "yellow",
        "LOW": "cyan",
        "INFO": "dim",
    }

    # Risk score panel
    risk_color = "red" if result.risk_score >= 75 else "yellow" if result.risk_score >= 50 else "green"
    console.print(Panel.fit(
        f"[{risk_color}]Risk Score: {result.risk_score}/100[/{risk_color}]\n"
        f"Files scanned: {result.files_scanned}\n"
        f"Total findings: {len(result.filtered_findings)}\n"
        f"Scan duration: {result.scan_duration:.2f}s",
        title="Scan Summary",
    ))

    # Severity breakdown table
    sev_table = Table(title="Severity Breakdown", box=box.SIMPLE)
    sev_table.add_column("Severity", style="bold")
    sev_table.add_column("Count", justify="right")

    severity_counts = {}
    for f in result.filtered_findings:
        sev = f.get("severity", "MEDIUM").upper()
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        count = severity_counts.get(sev, 0)
        if count > 0:
            sev_table.add_row(f"[{severity_colors.get(sev, 'white')}]{sev}[/{severity_colors.get(sev, 'white')}]", str(count))

    console.print(sev_table)

    # Findings table
    if result.filtered_findings:
        findings_table = Table(title="Findings", box=box.SIMPLE, show_lines=True)
        findings_table.add_column("#", style="dim", width=4)
        findings_table.add_column("Severity", width=10)
        findings_table.add_column("Title", width=40)
        findings_table.add_column("File", width=30)
        findings_table.add_column("Line", width=6)
        findings_table.add_column("Source", width=15)

        for i, f in enumerate(result.filtered_findings[:50], 1):
            sev = f.get("severity", "MEDIUM").upper()
            sev_style = severity_colors.get(sev, "white")
            findings_table.add_row(
                str(i),
                f"[{sev_style}]{sev}[/{sev_style}]",
                f.get("title", "Unknown")[:40],
                f.get("file", "N/A")[-30:],
                str(f.get("line", "N/A")),
                f.get("source", f.get("agent", "unknown"))[:15],
            )

        console.print(findings_table)

    # Auto-fix suggestions
    if result.fixes:
        console.print(f"\n[bold green]Auto-fix Suggestions ({len(result.fixes)}):[/bold green]")
        for i, fix in enumerate(result.fixes[:20], 1):
            console.print(f"  {i}. [{severity_colors.get(fix.get('severity', 'INFO'), 'dim')}]{fix.get('title', 'Unknown')}[/{severity_colors.get(fix.get('severity', 'INFO'), 'dim')}]")
            if fix.get("fix"):
                console.print(f"     [dim]Fix: {fix['fix'][:100]}[/dim]")

    # Report locations
    if result.report_files:
        console.print("\n[bold]Reports generated:[/bold]")
        for fmt, path in result.report_files.items():
            console.print(f"  [{fmt}] {path}")

    # Stats
    if result.stats:
        console.print(f"\n[dim]Stats: {result.stats}[/dim]")

    return 0 if result.risk_score < 75 else 1


async def _run_scan_simple(args) -> int:
    """Simple scan output without Rich library."""
    config = ShieldConfig(config_path=args.config) if args.config else ShieldConfig()
    config.target_path = args.target

    if args.provider:
        config.llm.provider = args.provider
    if args.output:
        config.report.output_dir = args.output
    if args.no_cache:
        config.cache.enabled = False
    if args.no_dedup:
        config.deduplication.enabled = False
    if args.no_ignore:
        config.shieldignore.enabled = False
    if args.sarif_only:
        config.report.formats = ["sarif"]
    if args.ci:
        config.report.formats = ["sarif", "json"]

    setup_logging(args.verbose, args.debug)

    print(f"Shield Agents v{__version__} - Scanning {args.target}...")
    orchestrator = Orchestrator(config)
    result = await orchestrator.scan(
        target_path=args.target,
        full_scan=args.full,
        generate_report=not args.no_report,
        generate_fixes=args.fix,
    )

    # JSON format: output to stdout and exit
    if args.format == "json":
        output = result.to_dict()
        print(json.dumps(output, indent=2))
        threshold = getattr(args, 'fail_threshold', 75) or 75
        return 1 if result.risk_score >= threshold else 0

    print(f"\nRisk Score: {result.risk_score}/100")
    print(f"Files scanned: {result.files_scanned}")
    print(f"Findings: {len(result.filtered_findings)}")
    print(f"Duration: {result.scan_duration:.2f}s")

    if result.report_files:
        print("\nReports:")
        for fmt, path in result.report_files.items():
            print(f"  [{fmt}] {path}")

    return 0 if result.risk_score < 75 else 1


def run_init(args) -> int:
    """Initialize Shield Agents configuration."""
    path = args.path
    template_path = ShieldIgnore.create_template(path)
    print(f"Created .shieldignore template at: {template_path}")

    # Also create a default config
    config_path = Path(path) / "config.yaml"
    if not config_path.exists():
        config_content = """# Shield Agents Configuration
llm:
  provider: mock  # mock, openai, anthropic, ollama
  # api_key: YOUR_API_KEY  # Or set SHIELD_LLM_API_KEY env var
  model: gpt-4
  temperature: 0.1

scanner:
  sast_enabled: true
  secrets_enabled: true

cache:
  enabled: true
  incremental: true

deduplication:
  enabled: true
  merge_sources: true

report:
  output_dir: ./shield-reports
  formats:
    - html
    - sarif
    - json
"""
        Path(path).mkdir(parents=True, exist_ok=True)
        config_path.write_text(config_content)
        print(f"Created config template at: {config_path}")

    return 0


def run_cache(args) -> int:
    """Manage scan cache."""
    cache = ScanCache()
    cache._ensure_loaded()

    if args.clear:
        cache.clear()
        cache.save()
        print("Cache cleared.")
    elif args.stats:
        stats = cache.get_stats()
        print(f"Cached files: {stats['cached_files']}")
        print(f"Total cached findings: {stats['total_cached_findings']}")
        print(f"Cache size: {stats['cache_size_bytes']} bytes")
    else:
        print("Use --clear or --stats")

    return 0


def main():
    """Main entry point."""
    parser = create_parser()
    args = parser.parse_args()

    if args.command is None:
        parser.print_help()
        return 0

    if args.command == "version":
        print(f"Shield Agents v{__version__}")
        return 0

    if args.command == "init":
        return run_init(args)

    if args.command == "cache":
        return run_cache(args)

    if args.command == "scan":
        try:
            if args.ci:
                return asyncio.run(run_scan_ci(args))
            return asyncio.run(run_scan(args))
        except KeyboardInterrupt:
            print("\nScan interrupted.")
            return 130

    return 0


if __name__ == "__main__":
    sys.exit(main())
