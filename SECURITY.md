# Security Architecture & Threat Model

> Status: early alpha / active dogfooding (using the project in real workflows to discover defects before wider release).
> Scope: Linux and WSL2.

AgentPorter exposes local development capabilities to MCP clients, so security
boundaries are part of the product contract.

## 1. Direct execution vs. worker delegation

### Direct execution: kernel-isolated

`exec_run` and `exec_start` execute through Bubblewrap:

- target workspace mounted read-write or read-only according to configuration;
- private `/tmp`;
- host home, SSH credentials, Windows mounts, and Docker sockets omitted;
- read-only system runtimes;
- cleared environment and synthetic `HOME=/tmp`;
- unshared network namespace with outbound networking disabled;
- bounded synchronous output;
- bounded async job logs and execution timeout.

AgentPorter does not yet impose cgroup CPU/memory quotas. Treat time and output
limits as denial-of-service mitigation, not complete resource accounting.

### Worker delegation: host-user boundary

`dispatch_agent` launches installed coding-agent CLIs as the host user because
those programs normally require provider credentials and network access.

Consequences:

<<<<<<< HEAD
- worker CLIs are **not** contained by AgentPorter's Bubblewrap sandbox;
- worker processes may access whatever the host account and their own CLI
  sandbox/policy allow;
- a read-only workspace is only eligible for an adapter that can enforce
  read-only execution at the CLI level;
- prompt wording is not treated as a security boundary;
- model/reasoning overrides are accepted only when the adapter can actually
  enforce them.
=======
1. **Local-First Default**:
   AgentPorter binds strictly to `127.0.0.1`. Remote access should only occur through controlled, authenticated tunnels (e.g., Microsoft Dev Tunnels, Tailscale).
2. **Strict Host Header Validation**:
   Requests must match configured allowed hosts (e.g. `127.0.0.1`, `localhost`, `*.devtunnels.ms`). Unrecognized `Host` headers are rejected with `403 Forbidden` to prevent DNS rebinding attacks.
3. **API Key Authentication**:
   - Every request must provide a valid API key via header (`X-AgentPorter-Key` or legacy `X-M3-MCP-Key`).
   - Comparisons are performed in constant time using `hmac.compare_digest`.
   - Keys are stored in `~/.config/agentporter/secrets.env` with file permissions `0600`.
4. **Rate Limiting & Payload Ceiling**:
   - In-memory sliding window rate limiter (default: 120 requests/minute per client).
   - Maximum HTTP request payload size: 10 MB.
>>>>>>> origin/main

Users should only enable `allow_agent_dispatch` for workspaces where this
host-level trust is acceptable.

## 2. Ingress security

AgentPorter defaults to:

- bind address `127.0.0.1`;
- API-key authentication using `X-AgentPorter-Key`;
- only localhost Host headers;
- constant-time key comparison;
- per-client rate limiting;
- a request-body ceiling enforced both from `Content-Length` and actual ASGI
  body bytes.

Remote access is opt-in. Add only the specific tunnel/reverse-proxy hostname you
control to `allowed_hosts`. Broad tunnel-domain wildcards are not defaults.

Client-specific legacy header names are also opt-in local configuration.

## 3. Workspace and filesystem boundary

Every file-oriented request uses a registered `workspace_id`.

AgentPorter blocks:

- absolute paths;
- `..` traversal;
- symlink escapes outside the workspace root;
- access to sensitive path components such as `.git`, `.ssh`, `.env*`,
  private-key files, and `secrets.env`.

Search applies the same sensitive-path policy; it must not be usable to reveal
content that `read_file` would reject.

Large reads, writes, patches, Git output, job output, and artifact responses are
bounded.

## 4. Workspace capability controls

A local workspace may independently allow or deny:

- direct execution;
- Git inspection;
- artifact access;
- worker-agent dispatch;
- exact loopback HTTP ports.

`writable: false` controls file mutation and direct sandbox mounts. Worker
agents additionally require an adapter capable of enforcing read-only mode.

## 5. Loopback HTTP

`local_http_request` executes from the host-side AgentPorter process and can
reach loopback services. It is therefore a separate host-level trust boundary,
not sandboxed execution.

It is disabled by default for each workspace. A request is allowed only when
the destination port appears in that workspace's `local_http_ports` list.
Redirect following is disabled.

## 6. Git inspection

Only read operations are exposed: status, diff, log, and show. AgentPorter
suppresses global/system Git configuration, external diff helpers, fsmonitor,
and pagers where practical, and bounds returned output.

Repository-local Git configuration still exists on the host, so Git inspection
should be used only for registered workspaces the host user trusts.

## 7. Runtime state

Configuration/state directories are private where the OS supports POSIX modes.
Secrets and runtime logs/databases are not source-controlled. API-key files,
job databases, and execution logs use restrictive permissions.

Job records can contain commands or delegated prompts. Treat the state directory
as sensitive and apply normal backup/retention discipline.

## 8. Runtime provenance

Worker stdout/stderr are untrusted model output and are not accepted as proof of
which model executed a task. If a CLI does not provide a trusted machine-readable
provenance channel, AgentPorter reports the actual model as `unknown`.

## 9. Reporting vulnerabilities

Do not publish credentials or exploit details in a public issue. Use GitHub
Private Vulnerability Reporting when available or contact the maintainer
privately.
