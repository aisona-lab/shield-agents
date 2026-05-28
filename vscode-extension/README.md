# Shield Agents - VS Code Extension

Real-time security scanning powered by Shield Agents AI. Detects vulnerabilities, secrets, and compliance issues as you code.

## Features

- **Scan on Save**: Automatically scans files when you save them
- **Workspace Scan**: Scan your entire project with a single command
- **Inline Diagnostics**: Security findings appear directly in the editor
- **Severity Highlighting**: Critical, High, Medium, Low color-coded indicators
- **Quick Fix Suggestions**: Remediation advice for each finding

## Requirements

- Python 3.8+ with `shield-agents` package installed
- VS Code 1.75+

## Installation

1. Install the Shield Agents Python package:
   ```bash
   pip install shield-agents
   ```

2. Install this extension in VS Code

## Configuration

| Setting | Default | Description |
|---------|---------|-------------|
| `shieldAgents.scanOnSave` | `true` | Automatically scan files on save |
| `shieldAgents.provider` | `mock` | LLM provider (mock, openai, anthropic, ollama) |
| `shieldAgents.apiKey` | `""` | API key for the LLM provider |
| `shieldAgents.enableSAST` | `true` | Enable SAST scanning |
| `shieldAgents.enableSecrets` | `true` | Enable secrets detection |
| `shieldAgents.minSeverity` | `LOW` | Minimum severity to display |

## Commands

- `Shield Agents: Scan Current File` - Scan the active file
- `Shield Agents: Scan Workspace` - Scan the entire workspace
- `Shield Agents: Show Last Report` - Display the last scan report
- `Shield Agents: Clear Cache` - Clear the scan cache
