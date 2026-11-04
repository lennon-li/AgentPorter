# Contributing to AgentPorter

Thank you for contributing to AgentPorter!

## Development Setup

1. **Prerequisites**:
   - Linux or WSL2 (Ubuntu 22.04+ recommended)
   - Python 3.11+
   - `bubblewrap` (`sudo apt install bubblewrap`)
   - `ripgrep` (`sudo apt install ripgrep`)
   - `patch` (`sudo apt install patch`)
   - `git`

2. **Clone & Virtual Environment**:
   ```bash
   git clone https://github.com/lennon-li/AgentPorter.git
   cd AgentPorter
   uv venv .venv
   source .venv/bin/activate
   uv pip install -e ".[dev]"
   ```

## Running Tests

AgentPorter maintains strict test coverage across unit logic, integration workflows, and security regression gates:

```bash
# Run the entire test suite
pytest -v tests/

# Run only security boundary tests
pytest -v tests/security/

# Run unit tests
pytest -v tests/unit/
```

## Security Invariants to Maintain

When proposing code changes, ensure you never:
- Allow absolute path resolution in workspace tools.
- Enable network access in `bubblewrap` arguments.
- Mount `/home`, `/mnt/c`, or host secret directories inside the sandbox.
- Log raw API keys or credentials.
- Commit private configurations, databases, or API keys into git.
