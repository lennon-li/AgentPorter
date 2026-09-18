# AgentPorter

> A secure, local-first Model Context Protocol (MCP) gateway for controlled development workspaces, sandboxed code execution, Git inspection, artifact retrieval, and AI coding agent delegation.

---

## What is AgentPorter?

AgentPorter is a local-first MCP gateway that gives MCP-capable AI clients controlled access to development workspaces, sandboxed code execution, Git, artifacts, and installed AI coding agents.

It was designed to bridge interactive orchestrators (such as Microsoft Copilot Studio, Claude Desktop, LibreChat, or custom agents) with local development environments while maintaining strict security boundaries around filesystem access, execution, and credentials.

### Key Capabilities

- **Local-First & Client-Agnostic**: Implements the standard Model Context Protocol over Streamable HTTP with API-key authentication and strict Host-header validation.
- **Controlled Workspace Access**: Replaces raw filesystem access with registered workspace identifiers. Operations enforce project-relative paths, block traversal sequences (`..`), prevent symlink escapes, and prohibit access to sensitive credentials (`.ssh`, `.env`, `.git`).
- **Sandboxed Direct Execution**: Executes code (Bash, Python, R) within unprivileged Linux `bubblewrap` (bwrap) sandboxes with memory-backed private `/tmp`, unshared network namespaces (zero outbound network), and scrubbed environments.
- **Asynchronous Jobs & Output Tailing**: Manages long-running commands and test suites asynchronously with SQLite tracking, incremental output cursors, and clean process-group cancellation.
- **Read-Only Git Operations**: Exposes safe, non-destructive inspection tools (`git_status`, `git_diff`, `git_log`, `git_show`). State-changing Git operations (commit, push, force-reset) are explicitly forbidden.
- **Worker-Agent Delegation**: Dispatches specialist tasks or independent code reviews to installed AI coding agent CLIs (such as Codex, Claude Code, OpenCode, and Antigravity) with structured control packets and telemetry tracking.

---

## ⚠️ Security Notice: Trust Boundaries

AgentPorter maintains two fundamentally different execution trust boundaries:

1. **Direct Execution (`exec_run`, `exec_start`)**:
   - **Strongly Sandboxed**: Executed inside unprivileged `bubblewrap` namespaces.
   - Network namespace is completely disabled (`--unshare-net`).
   - Host home, credentials, `/mnt/c`, and Docker sockets are absent from the mount table.
   - User identity is synthetic (`sandbox:x:1000:1000`).

2. **Worker CLI Delegation (`dispatch_agent`)**:
   - **Runs as Host User**: Installed CLI agents (e.g. `codex`, `claude`, `opencode`, `agy`) require host credentials and user tokens (such as `~/.codex`, `~/.claude`) to reach their respective LLM providers.
   - Worker agents execute outside the kernel Bubblewrap sandbox and are bounded by working directory scoping and prompt discipline.
   - **Do not treat worker agent delegation as equivalent to sandboxed execution.**

See [SECURITY.md](SECURITY.md) and [docs/security-model.md](docs/security-model.md) for full architectural details.

---

## Platform Support & Status

- **Status**: Early alpha / active dogfooding.
- **Platform**: Linux and WSL2 (Ubuntu 22.04+). Bubblewrap (`bwrap`) is required for sandboxed execution.

---

## Installation

```bash
# Clone the repository
git clone https://github.com/lennon-li/AgentPorter.git
cd AgentPorter

# Install with pip / uv
pip install -e .
# or with development dependencies:
pip install -e ".[dev]"
```

---

## Quick Start

### 1. Check System Health

```bash
agentporter doctor
```

`doctor` verifies Python version, Bubblewrap availability, configuration directories, and detected CLI agent workers.

### 2. Configure Workspaces

Create `~/.config/agentporter/workspaces.yaml`:

```yaml
workspaces:
  my-project:
    path: /path/to/project
    writable: true
    description: "Primary development project"
```

### 3. Run the Server

```bash
agentporter serve --host 127.0.0.1 --port 8765
```

On initial startup, an API key is generated and stored securely in `~/.config/agentporter/secrets.env` (file mode `0600`).

---

## Documentation

- [Architecture Overview](docs/architecture.md)
- [Security Model & Threat Matrix](docs/security-model.md)
- [Package vs. Local Separation](docs/package-vs-local.md)
- [Local Installation & Setup Guide](docs/local-setup.md)
- [Connecting MCP Clients](docs/mcp-clients.md)
- [Microsoft Copilot Studio Setup](docs/copilot-studio.md)

---

## Contributing & Development

See [CONTRIBUTING.md](CONTRIBUTING.md) for test execution instructions and guidelines.

To run the test suite:

```bash
pytest -v tests/
```
