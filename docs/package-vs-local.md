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

## Local installation

Mutable deployment state belongs under standard XDG locations:

### `~/.config/agentporter/`

- `config.yaml`: server/security/sandbox configuration.
- `workspaces.yaml`: local workspace registrations and permissions.
- `secrets.env`: AgentPorter API key, mode `0600`.

### `~/.local/state/agentporter/`

- `jobs.db`: job metadata.
- `jobs/*.stdout.log`, `jobs/*.stderr.log`: bounded job output.
- `logs/agentporter.log`: server/security audit log.
- `etc/passwd`, `etc/group`: synthetic sandbox identity files.

State/config directories are created with private permissions where supported.

### `~/.cache/agentporter/`

Reserved for disposable cache data. It is never part of the source package.

## User workspaces

Actual projects remain outside AgentPorter, for example:

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

A workspace registration is an authorization boundary. The package never assumes
a user's home path, repository names, preferred agents, or provider routing.

## Client-specific deployment repositories

Users may keep a separate private deployment/configuration repository for a
specific MCP client or agent system. Such a repo can contain sanitized setup
scripts, client instructions, and local policy templates, but secrets and
mutable runtime state should still remain outside Git.

This allows AgentPorter itself to remain client-agnostic while personal
deployments can be opinionated.
