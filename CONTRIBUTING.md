# Contributing to Shield Agents

First off, thank you for considering contributing to Shield Agents! It's people like you that make this tool better for everyone.

## How to Contribute

### Reporting Bugs

Before creating bug reports, please check the existing issues. When you create a bug report, include as many details as possible:

- **OS and Python version**
- **Shield Agents version** (`shield-agents version`)
- **Steps to reproduce**
- **Expected vs actual behavior**
- **Scan output or error messages**

### Suggesting Enhancements

Enhancement suggestions are tracked as GitHub issues. Include:

- **Use case** - why is this needed?
- **Expected behavior** - what should it do?
- **Current workaround** - is there an alternative?

### Pull Requests

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Run the test suite:
   ```bash
   pip install -e ".[dev]"
   pytest tests/ -v
   python -m benchmarks.benchmark
   ```
5. Ensure code style:
   ```bash
   ruff check shield_agents/
   black --check shield_agents/
   ```
6. Commit with a clear message (`git commit -m 'Add amazing feature'`)
7. Push to the branch (`git push origin feature/amazing-feature`)
8. Open a Pull Request

### Adding New SAST Rules

1. Add the rule to `shield_agents/scanners/sast.py` in the `SAST_RULES` list
2. Add a test case in `tests/test_sast.py`
3. Add a benchmark case in `benchmarks/benchmark.py` (optional but recommended)
4. Update the README with the new rule

### Adding New Secret Patterns

1. Add the pattern to `shield_agents/scanners/secrets.py` in `SECRET_PATTERNS`
2. Add a test case in `tests/test_secrets.py`
3. Consider entropy filtering to reduce false positives

### Adding New Agents

1. Create a new file in `shield_agents/agents/`
2. Extend `BaseAgent` and implement `analyze()` and `get_system_prompt()`
3. Add agent-specific patterns to the MockProvider in `llm.py`
4. Register in `shield_agents/agents/__init__.py`
5. Add configuration in `config.py`
6. Wire into the orchestrator in `orchestrator.py`
7. Add tests and update README

## Development Setup

```bash
# Clone the repository
git clone https://github.com/shield-agents/shield-agents.git
cd shield-agents

# Create a virtual environment
python -m venv venv
source venv/bin/activate  # Linux/Mac
# or venv\Scripts\activate on Windows

# Install with dev dependencies
pip install -e ".[dev]"

# Run tests
pytest tests/ -v

# Run benchmarks
python -m benchmarks.benchmark --verbose

# Run linter
ruff check shield_agents/
```

## Code Style

- Follow PEP 8
- Use type hints
- Maximum line length: 100 characters
- Use `ruff` for linting
- Use `black` for formatting

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
