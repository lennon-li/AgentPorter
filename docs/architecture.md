# AgentPorter Architecture

## 1. System Overview

AgentPorter is an MCP gateway designed to provide AI orchestration clients (such as Microsoft Copilot Studio, Claude Desktop, or custom MCP agents) with safe, auditable access to local development workspaces.

```text
┌────────────────────────────────────────────────────────┐
│                   MCP Client Application               │
│          (Copilot Studio, Claude Desktop, etc.)        │
└───────────────────────────┬────────────────────────────┘
                            │ HTTPS / Streamable HTTP
                            │ (Header Auth: X-AgentPorter-Key / X-M3-MCP-Key)
                            ▼
┌────────────────────────────────────────────────────────┐
│                  AgentPorter Server                    │
│                                                        │
│  ┌──────────────────────────────────────────────────┐  │
│  │              Security Middleware                 │  │
│  │   • Host Validation    • API-Key Auth (HMAC)     │  │
│  │   • Rate Limiting      • Payload Ceiling         │  │
│  └──────────────────────────┬───────────────────────┘  │
│                             ▼                          │
│  ┌──────────────────────────────────────────────────┐  │
│  │                 Tool Routers                     │  │
│  │  • System/Workspace    • Files & Search          │  │
│  │  • Git Inspection      • Artifacts               │  │
│  │  • Execution & Jobs    • Agent Broker            │  │
│  └──────────────┬──────────────────────┬────────────┘  │
└─────────────────┼──────────────────────┼───────────────┘
                  │                      │
       Direct Code Execution      Worker Agent Dispatch
                  │                      │
                  ▼                      ▼
    ┌────────────────────────┐  ┌────────────────────────┐
    │   Bubblewrap Sandbox   │  │   Agent Adapter CLI    │
    │                        │  │                        │
    │ • Zero network access  │  │ • Runs as host user    │
    │ • Cleaned environment  │  │ • Accesses auth tokens │
    │ • Read-only system OS  │  │ • Scoped by directory  │
    │ • Workspace RW/RO      │  │ • Structured telemetry │
    └────────────────────────┘  └────────────────────────┘
```

---

## 2. Core Subsystems

### A. Workspaces (`src/agentporter/workspaces/`)
Instead of allowing arbitrary filesystem paths, clients reference registered workspace identifiers (e.g. `workspace_id: "analytics"`).
- `registry.py`: Loads workspace definitions from local configuration.
- `paths.py`: Normalizes project-relative paths, prevents path traversal (`..`), detects symlink escapes outside the workspace root, and blocks access to sensitive directories (`.git`, `.ssh`, `.env`, keyfiles).

### B. Sandboxed Execution (`src/agentporter/sandbox/`)
Arbitrary script execution presents significant risk (subshells, network exfiltration, credential harvesting).
- `base.py`: Defines the `SandboxBackend` abstract interface.
- `bubblewrap.py`: Linux `bwrap` unprivileged namespace isolation:
  - `--unshare-all`, `--unshare-net` (no outbound networking).
  - Memory `/tmpfs` for temporary files.
  - Mounts target workspace at `/workspace`.
  - Synthetic `/etc/passwd` and `/etc/group`.
  - `--clearenv` to scrub all host secrets.

### C. Asynchronous Jobs (`src/agentporter/tools/jobs.py`)
Long-running commands (e.g. test suites or agent reviews) run asynchronously.
- Backed by an SQLite database (`jobs.db`) located in `$XDG_STATE_HOME/agentporter/`.
- Non-blocking execution with process groups for reliable SIGTERM/SIGKILL termination.
- Incremental output cursors for log streaming.

### D. Agent Broker & Adapters (`src/agentporter/agents/`)
Specialized AI coding assistants (Codex, Claude, OpenCode, Agy) are integrated via clean adapter contracts.
- `broker.py`: Handles agent listing, preflight checks, control packet creation, and dispatch.
- `adapters/`: Individual CLI wrappers that handle CLI arguments, configuration parsing, and model/version detection.
- Provenance telemetry records worker CLI, provider, requested model, actual model, reasoning level, CLI version, and duration.
