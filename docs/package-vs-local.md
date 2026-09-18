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

The GitHub repository `lennon-li/AgentPorter` contains exclusively:

1. **Python Source Code (`src/agentporter/`)**:
   - Generic MCP tool implementations (`files`, `git`, `execution`, `jobs`, `artifacts`, `local_http`, `agents`).
   - Abstract sandbox contracts and the unprivileged Bubblewrap backend.
   - Abstract worker-agent adapter contracts (`codex`, `claude`, `opencode`, `agy`).
   - Authentication and security middleware (constant-time API key verification, host validation, rate limiting).
   - Provenance telemetry extractors.
   - CLI command definitions (`agentporter serve`, `doctor`, etc.).

2. **Packaging & Tooling**:
   - `pyproject.toml`, `.gitignore`, build specifications.

3. **Tests & Safe Fixtures (`tests/`)**:
   - Unit tests running in isolated `pytest` `tmp_path` fixtures.
   - Security regression tests verifying that path traversal, shell escapes, environment leakage, and sensitive file accesses are blocked.

4. **Sanitized Examples & Documentation (`examples/`, `docs/`)**:
   - Generic examples with placeholder paths (`/home/user/my-project`).
   - Setup guides for clients (Copilot Studio, Claude Desktop).

### Strict Negative Invariants: What MUST NEVER Enter the Package

- ❌ Host API keys or bearer tokens (`M3_MCP_KEY`, `AGENTPORTER_API_KEY`).
- ❌ Cloudflare Quick Tunnel credentials, domains, or PID files.
- ❌ Hardcoded `/home/yeli` or user-specific home paths.
- ❌ Real workspace registrations containing private paths.
- ❌ Host SSH keys (`id_rsa`, `id_ed25519`, `known_hosts`).
- ❌ LLM CLI provider auth tokens or caches (`~/.codex`, `~/.claude`, `~/.config/opencode`).
- ❌ SQLite job databases (`jobs.db`), stdout/stderr execution logs, or PID files.
- ❌ Generated artifacts or project plots.

---

## 3. Local Installation Scope (Lennon's Host or Any End User)

When installed on a machine (such as `wsl-pho`), AgentPorter conforms to the standard Linux XDG directory conventions:

### Config Directory (`$XDG_CONFIG_HOME/agentporter` or `~/.config/agentporter`)

- `config.yaml`: Global server parameters (bind address, port, rate limits, enabled adapters).
- `workspaces.yaml`: Registered workspace IDs mapping to local paths:
  ```yaml
  workspaces:
    m3-poc:
      path: /home/yeli/m3-agent-poc
      writable: true
      description: "Acceptance test workspace"
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

## 4. Preservation of Existing M3 Gateway

During the bootstrapping and development of AgentPorter:
- The existing gateway at `~/m3-agent-gateway` remains completely untouched, operating on port 8000.
- The active Cloudflare tunnel and Copilot Studio connection continue pointing to `~/m3-agent-gateway`.
- AgentPorter runs independently on a separate port (e.g. 8765) with its own state and configurations.
- Migration will only occur in a future, explicitly scheduled phase after complete parity acceptance.
