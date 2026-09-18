# AgentPorter

> A local-first Model Context Protocol (MCP) gateway for controlled development
> workspaces, sandboxed code execution, Git inspection, artifacts, and AI coding
> agent delegation.

AgentPorter lets MCP-capable clients work with local development environments
without giving the client unrestricted host access.

## Current capabilities

- **Workspace-scoped access** using registered workspace IDs instead of arbitrary host roots.
- **Sensitive-path controls** shared by file reads, writes, patches, and search.
- **Sandboxed direct execution** for Bash, Python, R, and other installed runtimes through Bubblewrap.
- **No-network direct execution** with scrubbed environment and private `/tmp`.
- **Bounded async jobs** with SQLite state, cancellation, timeout, and output limits.
- **Read-only Git inspection** with bounded output and defensive Git configuration.
- **Artifact retrieval** with response-size limits.
- **Explicit loopback HTTP allowlists** per workspace.
- **Worker-agent delegation** through adapters for installed coding-agent CLIs.
- **Truthful provenance fields** that separate configured routing, requested overrides, and verified actual model.

## Trust boundaries

Direct code execution is kernel-isolated with Bubblewrap.

Worker-agent delegation is different: installed CLIs normally run as the host
user so they can access their own provider credentials and network. AgentPorter
therefore does not claim that delegated workers are sandboxed. A read-only
workspace can only dispatch an adapter that can enforce read-only behavior.

See [SECURITY.md](SECURITY.md).

## Status

**Early alpha / active dogfooding.**

"Dogfooding" means using your own product for real work while it is still under
development. The purpose is to discover failures, awkward interfaces, missing
controls, and real security requirements before designing features speculatively
or releasing broadly.

Current platform target: Linux and WSL2 with Python 3.11+ and Bubblewrap.

## Install

```bash
git clone https://github.com/lennon-li/AgentPorter.git
cd AgentPorter
pip install -e ".[dev]"
```

AgentPorter is not published to PyPI yet.

## Configure

Create `~/.config/agentporter/workspaces.yaml`:

```yaml
workspaces:
  my-project:
    path: /home/user/projects/my-project
    writable: true
    allow_execute: true
    allow_git: true
    allow_artifacts: true
    allow_agent_dispatch: false
    local_http_ports: []
```

The default server configuration binds only to localhost and uses the
`X-AgentPorter-Key` API-key header. On first startup, AgentPorter generates a
key in `~/.config/agentporter/secrets.env` with restrictive permissions.

## Run

```bash
agentporter doctor
agentporter serve --host 127.0.0.1 --port 8765
```

## Documentation

- [Architecture](docs/architecture.md)
- [Security model](docs/security-model.md)
- [Package vs. local separation](docs/package-vs-local.md)
- [Local setup](docs/local-setup.md)
- [MCP clients](docs/mcp-clients.md)
- [Microsoft Copilot Studio](docs/copilot-studio.md)

## Development

```bash
pytest -v tests/
```

The repository intentionally does not choose a public software license yet.
