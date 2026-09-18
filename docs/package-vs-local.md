# Package vs. Local Separation Architecture

> **Core Tenet**: The software repository (package) contains only generic, reusable code and safe configuration schemas. Mutable state, machine-specific configurations, credentials, runtime databases, logs, and user workspaces live strictly in local filesystem hierarchies.

---

## 1. The Separation Matrix

| Component | Location | Role / Scope | Git Tracking |
| :--- | :--- | :--- | :--- |
| **AgentPorter Core Software** | `src/agentporter/` | Generic MCP server, tools, sandbox logic, agent adapters, CLI | Tracked in Git |
| **Test Suites & Fixtures** | `tests/` | Unit, integration, and security tests with mock workspaces | Tracked in Git |
| **Example Configurations** | `examples/` | Sanitized templates (`config.example.yaml`, `workspaces.example.yaml`) | Tracked in Git |
| **Documentation** | `docs/`, `*.md` | Specifications, guides, threat model, API contracts | Tracked in Git |
| **Local Configuration** | `~/.config/agentporter/` | Active `config.yaml`, `workspaces.yaml`, `secrets.env` | **NEVER TRACKED** |
| **Local Runtime State** | `~/.local/state/agentporter/` | SQLite `jobs.db`, job logs, server PID, synthetic passwd/group | **NEVER TRACKED** |
| **Local Caching / Artifacts** | `~/.cache/agentporter/` | Ephemeral caches, temporary downloads | **NEVER TRACKED** |
| **User Workspaces** | e.g. `~/repos/*`, `~/projects/*` | Actual source code repositories registered by the host user | Outside AgentPorter |

---

## 2. Package Scope (What Goes in Git)

The repository contains exclusively:

1. **Python Source Code (`src/agentporter/`)**:
   - Generic MCP tool implementations (`files`, `git`, `execution`, `jobs`, `artifacts`, `local_http`, `agents`).
   - Abstract sandbox contracts and the unprivileged Bubblewrap backend.
   - Abstract worker-agent adapter contracts (`codex`, `claude`, `opencode`, `agy`).
   - Authentication and security middleware (constant-time API key verification, host validation, rate limiting).
   - Provenance telemetry extractors.
   - CLI command definitions (`agentporter serve`, `doctor`, `key`, etc.).

2. **Packaging & Tooling**:
   - `pyproject.toml`, `.gitignore`, build specifications.

3. **Tests & Safe Fixtures (`tests/`)**:
   - Unit tests running in isolated `pytest` `tmp_path` fixtures.
   - Security regression tests verifying that path traversal, shell escapes, environment leakage, and sensitive file accesses are blocked.

4. **Sanitized Examples & Documentation (`examples/`, `docs/`)**:
   - Generic examples with placeholder paths (`/home/user/my-project`).
   - Setup guides for clients (Copilot Studio, Claude Desktop).

### Strict Negative Invariants: What MUST NEVER Enter the Package

- ❌ Host API keys or bearer tokens.
- ❌ Tunnel credentials, domains, or token strings.
- ❌ Hardcoded usernames, home paths, or private hostnames.
- ❌ Real workspace registrations containing private paths.
- ❌ Host SSH keys (`id_rsa`, `id_ed25519`, `known_hosts`).
- ❌ LLM CLI provider auth tokens or caches (`~/.codex`, `~/.claude`, `~/.config/opencode`).
- ❌ SQLite job databases (`jobs.db`), stdout/stderr execution logs, or PID files.
- ❌ Generated artifacts or project plots.

---

## 3. Local Installation Scope

When installed on a target host, AgentPorter conforms to the standard Linux XDG directory conventions:

### Config Directory (`$XDG_CONFIG_HOME/agentporter` or `~/.config/agentporter`)

- `config.yaml`: Global server parameters (bind address, port, rate limits, enabled adapters).
- `workspaces.yaml`: Registered workspace IDs mapping to local paths:
  ```yaml
  workspaces:
    sample-project:
      path: /home/user/projects/sample-project
      writable: true
      description: "Development workspace"
  ```
- `secrets.env`: Permissions `0600`. Contains the generated API authentication key:
  ```env
  AGENTPORTER_API_KEY=vX48...
  ```

### State Directory (`$XDG_STATE_HOME/agentporter` or `~/.local/state/agentporter`)

- `jobs.db`: SQLite database storing job execution metadata, timings, exit statuses, and telemetry.
- `jobs/<job_id>.stdout.log` & `jobs/<job_id>.stderr.log`: Dedicated log streams for every command and agent dispatch.
- `logs/agentporter.log`: Rotating server audit logs capturing tool invocations, durations, and security rejections.
- `agentporter.pid`: Process ID file for daemon management.
- `etc/passwd` and `etc/group`: Synthetic minimal user identities for the Bubblewrap sandbox.

### Cache Directory (`$XDG_CACHE_HOME/agentporter` or `~/.cache/agentporter`)

- Ephemeral files, scratch artifacts, or temporary downloads.

---

## 4. Coexistence with Existing Services

AgentPorter can run alongside other gateways or services without conflict:
- Runs by default on its own dedicated port (e.g. 8765) with its own XDG state and configuration trees.
- Keeps sandbox state completely separated from any external processes.
