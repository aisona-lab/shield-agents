<div align="center">

# 🛡️ Shield Agents

### AI-Powered Multi-Agent Cybersecurity Scanner

[![Python 3.8+](https://img.shields.io/badge/python-3.8%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow?style=for-the-badge)](https://opensource.org/licenses/MIT)
[![Code Style: Ruff](https://img.shields.io/badge/code%20style-ruff-ff6b6b?style=for-the-badge)](https://github.com/astral-sh/ruff)
[![Tests: 52](https://img.shields.io/badge/tests-52%20passing-brightgreen?style=for-the-badge)]()
[![Benchmarks: 13/13](https://img.shields.io/badge/benchmarks-13%2F13-brightgreen?style=for-the-badge)]()

**Production-grade security analysis using coordinated AI agents.**  
Detect vulnerabilities, threats, secrets, and compliance issues — then auto-fix them.

[Getting Started](#-getting-started) · [Features](#-features) · [Architecture](#-architecture) · [CI/CD](#-cicd-integration) · [VS Code](#-vs-code-extension) · [Contributing](CONTRIBUTING.md)

</div>

---

## ✨ Why Shield Agents?

Most security scanners just find problems. Shield Agents **finds AND fixes them** using a team of specialized AI agents that work together like a real security team:

- 🔍 **VulnAgent** — Finds SQL injection, XSS, command injection, and more
- 🎯 **ThreatAgent** — Maps attack vectors to MITRE ATT&CK techniques
- 🕵️ **ReconAgent** — Detects information disclosure and exposed secrets
- 📋 **ComplianceAgent** — Checks against OWASP Top 10 2021
- 🚨 **ResponseAgent** — Provides risk assessment and incident response plans
- 🔧 **AutoFixAgent** — The "Master White Hat Hacker" that generates copy-paste-ready code fixes

Works out of the box with the **smart mock provider** — no API key needed to start scanning.

---

## 🚀 Getting Started

### Installation

```bash
# Install from source (mock provider included - no API key needed)
pip install -e .

# With OpenAI support
pip install -e ".[openai]"

# With all LLM providers (OpenAI + Anthropic + Ollama)
pip install -e ".[all]"

# With development tools
pip install -e ".[dev]"
```

### Your First Scan

```bash
# Scan a project (uses smart mock provider by default)
shield-agents scan ./my-project

# Scan with auto-fix suggestions
shield-agents scan ./my-project --fix

# Full scan (ignore cache, scan everything)
shield-agents scan ./my-project --full

# Initialize configuration files
shield-agents init
```

### Docker

```bash
# Build and scan
docker-compose up shield-agents

# With Ollama for local LLM
docker-compose up ollama shield-agents
```

---

## 🛡️ Features

### Core Scanning Engine

| Feature | Details |
|---------|---------|
| **SAST Scanner** | 10 detection rules: SQL Injection, XSS, Command Injection, Path Traversal, Insecure Deserialization, Weak Crypto, Auth Issues, Hardcoded Credentials, SSL/TLS Issues, SSRF |
| **Secrets Scanner** | 24 pattern types: AWS, GitHub, Google, Slack, Stripe, DB connections, JWTs, Private Keys, and generic secrets with Shannon entropy filtering |
| **6 AI Agents** | VulnAgent, ThreatAgent, ReconAgent, ComplianceAgent, ResponseAgent, AutoFixAgent |
| **Auto-Fix Engine** | Pattern-based instant fixes + LLM-powered deep remediation with copy-paste-ready code |

### Production Features (v2.0)

| # | Feature | Description |
|---|---------|-------------|
| 1 | **Smart Mock Provider** | Pattern-matched findings based on actual code content — demo mode feels real, not static |
| 2 | **Deduplication Engine** | 3-phase dedup (exact → fuzzy → category merge) — when VulnAgent and SAST both find "SQL Injection", they merge into one finding with multiple sources |
| 3 | **SARIF 2.1.0 Output** | GitHub Security tab integration — upload results directly to GitHub code scanning |
| 4 | **`.shieldignore` File** | Like `.gitignore` for false positives — 9 rule types (file, category, severity, rule, path, line, title, cwe, id) |
| 5 | **Caching / Incremental Scans** | Cache previous results, only re-scan changed files — production-ready performance |
| 6 | **LLM Fallback Parser** | 5-strategy parser for when LLMs return invalid JSON (~30% failure rate) — never crash on bad responses |
| 7 | **VS Code Extension** | On-save scanning with inline diagnostics — security issues appear directly in your editor |
| 8 | **Benchmark Suite** | 13 OWASP WebGoat-style test cases — proves the scanner actually finds real bugs |
| 9 | **CI/CD Mode** | `--ci` flag for pipelines — JSON to stdout, SARIF output, exit code based on risk threshold |
| 10 | **`--format json`** | Pipe results to other tools — structured JSON output for integration |
| 11 | **Auto-Exclude** | Tests, benchmarks, and examples automatically excluded from scan — eliminates ~70% false positives |
| 12 | **Agent-Differentiated Mock** | Each AI agent returns specialized findings in mock mode — VulnAgent finds vulns, ThreatAgent finds threats |

---

## 📋 CLI Reference

```bash
shield-agents scan <target> [options]

Options:
  --config, -c         Path to config YAML file
  --full               Full scan (ignore cache)
  --fix                Generate auto-fix suggestions
  --no-report          Skip report generation
  --sarif-only         Output only SARIF format
  --output, -o         Output directory for reports
  --provider           LLM provider: mock, openai, anthropic, ollama
  --format, -f         Output format: rich, json, sarif, plain (default: rich)
  --ci                 CI/CD mode: silent except JSON on stdout
  --fail-threshold     Risk score threshold for CI failure (default: 75)
  --no-cache           Disable caching
  --no-dedup           Disable deduplication
  --no-ignore          Ignore .shieldignore rules
  --verbose, -v        Verbose output
  --debug              Debug output

Commands:
  scan <target>        Run security scan
  init                 Create .shieldignore and config templates
  cache --stats        Show cache statistics
  cache --clear        Clear scan cache
  version              Show version info
```

---

## ⚙️ Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `SHIELD_LLM_PROVIDER` | LLM provider (mock, openai, anthropic, ollama) | `mock` |
| `SHIELD_LLM_API_KEY` | API key for the LLM provider | None |
| `SHIELD_LLM_MODEL` | Model name | `gpt-4` |
| `SHIELD_LLM_BASE_URL` | Custom API base URL (for Ollama) | None |
| `SHIELD_VERBOSE` | Enable verbose output | `false` |
| `SHIELD_DEBUG` | Enable debug output | `false` |

### Config File (`config.yaml`)

```yaml
llm:
  provider: mock          # mock, openai, anthropic, ollama
  model: gpt-4
  temperature: 0.1
  fallback_enabled: true  # Robust JSON fallback parser

scanner:
  sast_enabled: true
  secrets_enabled: true

cache:
  enabled: true
  incremental: true       # Only re-scan changed files

deduplication:
  enabled: true
  merge_sources: true     # Merge duplicate findings from different sources

report:
  output_dir: ./shield-reports
  formats:
    - html
    - sarif
    - json
```

### `.shieldignore` File

Suppress false positives with 9 rule types:

```gitignore
# Shield Agents Ignore File
category:information-disclosure    # Ignore all info-disclosure findings
severity:LOW                       # Ignore LOW and INFO findings
rule:SAST-001                      # Ignore a specific rule
file:test_app.py                   # Ignore all findings in a file
path:*test*                        # Ignore findings in test files
line:42:app.py                     # Ignore finding at specific line
title:Assertion*                   # Ignore findings with matching title (glob)
cwe:CWE-617                        # Ignore findings with matching CWE
id:VulnAgent-3                     # Ignore a specific finding by ID
```

---

## 🏗️ Architecture

```
shield-agents/
├── shield_agents/
│   ├── agents/                # 6 AI agents
│   │   ├── base.py            # Abstract base agent
│   │   ├── vuln.py            # Vulnerability detection
│   │   ├── threat.py          # Threat modeling & MITRE ATT&CK
│   │   ├── recon.py           # Reconnaissance & info disclosure
│   │   ├── compliance.py      # OWASP compliance checking
│   │   ├── response.py        # Incident response & risk assessment
│   │   └── autofix.py         # Auto-remediation (Master White Hat Hacker)
│   ├── scanners/              # Static analysis
│   │   ├── sast.py            # 10 SAST detection rules
│   │   └── secrets.py         # 24 secret type patterns
│   ├── report/                # Output generation
│   │   ├── generator.py       # HTML + JSON reports
│   │   └── sarif.py           # SARIF 2.1.0 for GitHub
│   ├── knowledge/             # Security knowledge bases
│   │   ├── owasp.py           # OWASP Top 10 2021
│   │   ├── mitre.py           # MITRE ATT&CK
│   │   └── cve.py             # Known CVE database
│   ├── utils/                 # Utilities
│   │   ├── crypto.py          # Hashing for cache
│   │   └── helpers.py         # File I/O, risk scoring
│   ├── config.py              # Configuration management
│   ├── llm.py                 # LLM providers + 5-strategy fallback parser
│   ├── deduplication.py       # 3-phase finding deduplication engine
│   ├── cache.py               # Incremental scan caching
│   ├── shieldignore.py        # .shieldignore file parser (9 rule types)
│   ├── orchestrator.py        # Central coordinator (6-phase pipeline)
│   └── cli.py                 # Rich-powered CLI
├── vscode-extension/          # VS Code extension
├── benchmarks/                # OWASP-style benchmark suite (13 cases)
├── tests/                     # 52 unit tests
├── examples/                  # Vulnerable example app
├── .github/                   # Issue/PR templates
├── CHANGELOG.md               # Version history
├── CONTRIBUTING.md            # Contribution guide
└── pyproject.toml             # Modern Python packaging
```

### 6-Phase Scan Pipeline

```
┌─────────────┐   ┌──────────────────┐   ┌───────────────┐
│  Phase 1     │   │  Phase 2          │   │  Phase 3       │
│  SAST Scan   │──▶│  AI Agent Analysis│──▶│  Deduplication │
│  + Secrets   │   │  (4 agents/file)  │   │  (3 phases)    │
└─────────────┘   └──────────────────┘   └───────────────┘
                                                  │
┌─────────────┐   ┌──────────────────┐   ┌───────────────┐
│  Phase 6     │   │  Phase 5          │   │  Phase 4       │
│  Reporting   │◀──│  Auto-Fix Gen     │◀──│  .shieldignore │
│  HTML/SARIF  │   │  (Pattern + LLM)  │   │  Filtering     │
└─────────────┘   └──────────────────┘   └───────────────┘
```

---

## 🔄 CI/CD Integration

### GitHub Actions

```yaml
name: Security Scan
on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.11'
      - name: Install Shield Agents
        run: pip install -e .
      - name: Run Security Scan
        run: shield-agents scan ./src --ci --fail-threshold 75
      - name: Upload SARIF
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: shield-reports/results.sarif
```

### GitLab CI

```yaml
security-scan:
  stage: test
  image: python:3.11-slim
  script:
    - pip install -e .
    - shield-agents scan ./src --ci --format json > scan-results.json
  artifacts:
    paths:
      - shield-reports/
    reports:
      sast: shield-reports/results.sarif
```

### Generic Pipeline (JSON to stdout)

```bash
# JSON output for any CI system
shield-agents scan ./src --ci --format json

# Exit code: 0 = pass, 1 = risk score exceeds threshold
shield-agents scan ./src --ci --fail-threshold 60
```

---

## 💻 VS Code Extension

Real-time security scanning directly in your editor:

- **Scan on Save** — Automatically scans files when you save
- **Inline Diagnostics** — Security findings appear as editor warnings/errors
- **Severity Highlighting** — Color-coded CRITICAL/HIGH/MEDIUM/LOW indicators
- **Quick Fix Suggestions** — Remediation advice for each finding
- **Workspace Scan** — Scan your entire project with one command

Install the extension from the `vscode-extension/` directory and configure via VS Code settings.

---

## 🤖 AI Assistant Compatibility

Shield Agents works seamlessly with AI coding assistants:

| Tool | How to Use |
|------|-----------|
| **Cursor** | Add `shield-agents scan` to `.cursorrules` for auto-scanning on changes |
| **Claude Code** | Run `shield-agents scan` in terminal, integrate findings into workflow |
| **GitHub Copilot** | VS Code extension provides inline security diagnostics alongside Copilot |
| **Aider** | Use `--fix` mode and pipe auto-fix suggestions for code modifications |
| **Windsurf** | CLI-based integration via terminal |

---

## 📊 Benchmark Suite

Verify detection accuracy with 13 OWASP WebGoat-style test cases:

```bash
python -m benchmarks.benchmark --verbose
```

| Category | Test Cases |
|----------|-----------|
| SQL Injection | String concat, format strings |
| XSS | DOM-based, template injection |
| Command Injection | os.system, subprocess |
| Path Traversal | User-controlled file paths |
| Insecure Deserialization | pickle, yaml, marshal |
| Weak Cryptography | MD5, SHA-1, random module |
| Hardcoded Secrets | Passwords, API keys, AWS credentials |
| SSL/TLS Issues | verify=False, unverified context |
| SSRF | User-controlled URLs |
| Auth Bypass | Assertion-based, session manipulation |
| Clean Code | Negative test (minimal findings) |

---

## 🧪 Running Tests

```bash
# Run all 52 unit tests
pytest tests/ -v

# Run specific test module
pytest tests/test_sast.py -v
pytest tests/test_secrets.py -v
pytest tests/test_llm.py -v

# Run benchmarks
python -m benchmarks.benchmark --verbose

# Lint
ruff check shield_agents/
```

---

## 🤝 Contributing

We love contributions! See [CONTRIBUTING.md](CONTRIBUTING.md) for detailed guidelines.

Quick start:

```bash
git clone https://github.com/shield-agents/shield-agents.git
cd shield-agents
pip install -e ".[dev]"
pytest tests/ -v
```

---

## 📄 License

MIT License — see [LICENSE](LICENSE) for details.

---

<div align="center">

### 🌐 En Español

**Shield Agents — Escáner de Ciberseguridad Multi-Agente con IA**

Shield Agents es una plataforma de análisis de seguridad de grado producción que utiliza agentes de IA coordinados para detectar vulnerabilidades, amenazas, secretos y problemas de cumplimiento en tu código fuente. No solo encuentra los problemas — los **arregla automáticamente**.

**Características principales:**

| Característica | Descripción |
|---------------|-------------|
| 🛡️ Escáner SAST | 10 reglas de detección: Inyección SQL, XSS, Inyección de Comandos, Path Traversal, Deserialización Insegura, Criptografía Débil, Problemas de Autenticación, Credenciales Hardcodeadas, SSL/TLS, SSRF |
| 🔑 Escáner de Secretos | 24 tipos de patrones: AWS, GitHub, Google, Slack, Stripe, conexiones DB, JWTs, Claves Privadas, con filtrado de entropía Shannon |
| 🤖 6 Agentes de IA | VulnAgent (vulnerabilidades), ThreatAgent (modelado de amenazas), ReconAgent (reconocimiento), ComplianceAgent (cumplimiento OWASP), ResponseAgent (respuesta a incidentes), AutoFixAgent (corrección automática — el "Hacker Ético Maestro") |
| 🔄 Motor de Deduplicación | 3 fases: coincidencia exacta → coincidencia difusa → fusión por categoría |
| 📋 Formato SARIF | Integración con la pestaña de Seguridad de GitHub |
| 🚫 Archivo `.shieldignore` | Como `.gitignore` pero para falsos positivos — 9 tipos de reglas |
| ⚡ Escaneo Incremental | Caché de resultados anteriores, solo re-escanea archivos modificados |
| 🔧 Auto-Fix | Correcciones instantáneas basadas en patrones + correcciones profundas con LLM |
| 💻 Extensión VS Code | Escaneo al guardar con diagnósticos inline |
| 🚀 Modo CI/CD | `--ci` para pipelines — JSON a stdout, SARIF, código de salida basado en riesgo |

**Inicio rápido:**

```bash
# Instalar (proveedor mock incluido — sin API key necesario)
pip install -e .

# Escanear un proyecto
shield-agents scan ./mi-proyecto

# Escanear con sugerencias de corrección automática
shield-agents scan ./mi-proyecto --fix

# Modo CI/CD
shield-agents scan ./src --ci --fail-threshold 75

# Inicializar configuración
shield-agents init
```

**Compatibilidad con asistentes de IA:**

Shield Agents es compatible con Cursor, Claude Code, GitHub Copilot, Aider y Windsurf. Funciona como una herramienta CLI estándar que se integra en cualquier flujo de trabajo de desarrollo.

**Contribuir:**

Las contribuciones son bienvenidas. Lee [CONTRIBUTING.md](CONTRIBUTING.md) para las guías detalladas. Los reportes de bugs, solicitudes de funcionalidades y pull requests son apreciados.

**Licencia:** MIT

---

If you find Shield Agents useful, please ⭐ star the repo — it helps others discover the project!

**Built with care for the security community**

</div>
