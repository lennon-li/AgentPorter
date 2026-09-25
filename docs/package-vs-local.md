# Package vs. Local Separation

AgentPorter separates reusable software from machine-specific deployment state.

## Package / Git repository

Tracked in Git:

- `src/agentporter/`: generic MCP server, tools, sandbox, adapters, CLI.
- `tests/`: isolated unit, integration, and security regression tests.
- `examples/`: sanitized configuration templates.
- `docs/`: generic architecture, security, and client-integration documentation.
- `pyproject.toml` and build metadata.

The package must not contain:

- API keys, bearer tokens, or provider credentials.
- Real tunnel hostnames or tunnel credentials.
- User-specific home paths or real workspace registrations.
- Provider CLI authentication caches.
- SQLite job databases, execution logs, PID files, or generated artifacts.
- Personal agent aliases, preferred model routing, or machine-specific provider choices.

<<<<<<< HEAD
## Local installation

Mutable deployment state belongs under standard XDG locations:
=======
The repository contains exclusively:

1. **Python Source Code (`src/agentporter/`)**:
   - Generic MCP tool implementations (`files`, `git`, `execution`, `jobs`, `artifacts`, `local_http`, `agents`).
   - Abstract sandbox contracts and the unprivileged Bubblewrap backend.
   - Abstract worker-agent adapter contracts (`codex`, `claude`, `opencode`, `agy`).
   - Authentication and security middleware (constant-time API key verification, host validation, rate limiting).
   - Provenance telemetry extractors.
   - CLI command definitions (`agentporter serve`, `doctor`, `key`, etc.).
>>>>>>> origin/main

### `~/.config/agentporter/`

- `config.yaml`: server/security/sandbox configuration.
- `workspaces.yaml`: local workspace registrations and permissions.
- `secrets.env`: AgentPorter API key, mode `0600`.

### `~/.local/state/agentporter/`

- `jobs.db`: job metadata.
- `jobs/*.stdout.log`, `jobs/*.stderr.log`: bounded job output.
- `logs/agentporter.log`: server/security audit log.
- `etc/passwd`, `etc/group`: synthetic sandbox identity files.

<<<<<<< HEAD
State/config directories are created with private permissions where supported.
=======
- ❌ Host API keys or bearer tokens.
- ❌ Tunnel credentials, domains, or token strings.
- ❌ Hardcoded usernames, home paths, or private hostnames.
- ❌ Real workspace registrations containing private paths.
- ❌ Host SSH keys (`id_rsa`, `id_ed25519`, `known_hosts`).
- ❌ LLM CLI provider auth tokens or caches (`~/.codex`, `~/.claude`, `~/.config/opencode`).
- ❌ SQLite job databases (`jobs.db`), stdout/stderr execution logs, or PID files.
- ❌ Generated artifacts or project plots.
>>>>>>> origin/main

### `~/.cache/agentporter/`

<<<<<<< HEAD
Reserved for disposable cache data. It is never part of the source package.

## User workspaces
=======
## 3. Local Installation Scope

When installed on a target host, AgentPorter conforms to the standard Linux XDG directory conventions:
>>>>>>> origin/main

Actual projects remain outside AgentPorter, for example:

<<<<<<< HEAD
```yaml
workspaces:
  project-a:
    path: /home/user/projects/project-a
    writable: true
    allow_execute: true
    allow_git: true
    allow_artifacts: true
    allow_agent_dispatch: false
    local_http_ports: []
```
=======
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
>>>>>>> origin/main

A workspace registration is an authorization boundary. The package never assumes
a user's home path, repository names, preferred agents, or provider routing.

## Client-specific deployment repositories

Users may keep a separate private deployment/configuration repository for a
specific MCP client or agent system. Such a repo can contain sanitized setup
scripts, client instructions, and local policy templates, but secrets and
mutable runtime state should still remain outside Git.

<<<<<<< HEAD
This allows AgentPorter itself to remain client-agnostic while personal
deployments can be opinionated.
=======
- Ephemeral files, scratch artifacts, or temporary downloads.

---

## 4. Coexistence with Existing Services

AgentPorter can run alongside other gateways or services without conflict:
- Runs by default on its own dedicated port (e.g. 8765) with its own XDG state and configuration trees.
- Keeps sandbox state completely separated from any external processes.
>>>>>>> origin/main
