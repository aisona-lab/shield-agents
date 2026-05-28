# Changelog

All notable changes to Shield Agents will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.0.0] - 2025-05-29

### Added
- Smart Mock Provider with pattern-matched findings based on actual code content
- Deduplication Engine (3-phase: exact match, fuzzy match, category merge)
- SARIF 2.1.0 output for GitHub Security tab integration
- `.shieldignore` file support with 9 rule types
- Caching and incremental scanning
- LLM Fallback Handling with 5-strategy response parser
- VS Code Extension with on-save scanning and inline diagnostics
- Benchmark Suite with 13 OWASP WebGoat-style test cases
- Auto-Fix Agent (Master White Hat Hacker) with pattern-based and LLM fixes
- Agent-differentiated mock provider (each agent returns specialized findings)
- `--ci` mode for CI/CD pipelines (SARIF output, JSON to stdout, exit code based on risk)
- `--format json` for piping results to other tools
- Auto-exclude test/benchmark/examples directories from scan
- Migrated from setup.py to pyproject.toml

### Changed
- Mock provider now returns agent-specific findings instead of generic responses
- CLI now supports `--format` flag with rich/json/sarif/plain options
- Orchestrator auto-excludes content directories (tests, benchmarks, examples)

### Fixed
- `shield-agents init` crash when config directory doesn't exist
- JWT test assertion mismatch
- SAST missing patterns for path traversal and SSRF
