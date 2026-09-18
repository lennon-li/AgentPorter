# Security Architecture & Threat Model

> **Status**: Early Alpha / Active Dogfooding.
> **Scope**: Linux and WSL2 environments.

AgentPorter provides a multi-layer defense-in-depth model for exposing local development capabilities to AI orchestration clients via the Model Context Protocol (MCP).

---

## 1. Core Trust Boundaries (CRITICAL)

AgentPorter strictly distinguishes between two execution boundaries:

```
                  ┌──────────────────────────────────────────────┐
                  │                MCP Client                    │
                  │   (Copilot Studio / Claude Desktop / etc.)   │
                  └──────────────────────┬───────────────────────┘
                                         │  HTTPS / Streamable HTTP
                                         ▼
                  ┌──────────────────────────────────────────────┐
                  │             AgentPorter Server               │
                  │  (Host validation, Rate limit, API-Key Auth) │
                  └───────┬──────────────────────────────┬───────┘
                          │                              │
             Direct Code Execution                Worker Delegation
             (exec_run, exec_start)                (dispatch_agent)
                          │                              │
                          ▼                              ▼
             ┌─────────────────────────┐    ┌─────────────────────────┐
             │   BUBBLEWRAP SANDBOX    │    │    HOST USER CONTEXT    │
             │                         │    │                         │
             │ • Unshared network (OFF)│    │ • Runs as host user     │
             │ • Cleared environment   │    │ • Reads host auth cache │
             │ • Memory tmpfs /tmp     │    │   (~/.codex, ~/.claude) │
             │ • Host secrets ABSENT   │    │ • Scoped by cwd & prompt│
             │ • Synthetic user ID     │    │   DISCIPLINE ONLY       │
             └─────────────────────────┘    └─────────────────────────┘
                 [STRONGLY ISOLATED]            [NOT SANDBOXED]
```

### Boundary A: Direct Code Execution (`exec_run`, `exec_start`)
- **Strong Isolation**: Executed using Linux unprivileged user namespaces via `bwrap` (Bubblewrap).
- **Network Isolation**: `--unshare-net` completely severs network connectivity. Outbound sockets fail immediately with `Network is unreachable`.
- **Filesystem Isolation**:
  - The target workspace is mounted at `/workspace` (read-only or read-write per configuration).
  - Memory-backed private `/tmp` (`--tmpfs /tmp`).
  - Standard system binaries (`/usr`, `/lib`, `/bin`) are mounted read-only.
  - Sensitive host directories (`~/.ssh`, `~/.config`, `/home`, `/mnt/c`, `/var/run/docker.sock`) are **omitted from the mount table** and do not exist in the container.
  - Synthetic `/etc/passwd` and `/etc/group` provide isolated identity (`sandbox:x:1000:1000`) without exposing host user accounts.
- **Environment Scrubbing**: `--clearenv` discards all host environment variables, tokens, API keys, and secrets.

### Boundary B: Worker Agent Delegation (`dispatch_agent`)
- **⚠️ Host User Execution (Different Boundary)**:
  Installed worker agents (e.g. OpenAI Codex, Anthropic Claude Code, OpenCode, Antigravity) are executed **outside** the kernel Bubblewrap sandbox as the host user.
  This is currently necessary because worker CLIs require access to their own authentication tokens, local credential caches, and external LLM provider APIs over the network.
- **Bounding & Controls**:
  - Strict parameterization (`argv` lists without shell interpolation).
  - Explicit control blocks passed to the agent (`Permission Level: 1`, `AUTONOMOUS`, step budgets, target directory scoping).
  - Preflight Git checks and execution logging.
- **Caution**: Worker delegation relies on the worker CLI's internal safety policies and prompt framing. **It does not provide kernel-level sandboxing.**

---

## 2. Ingress & Transport Security

1. **Local-First Default**:
   AgentPorter binds strictly to `127.0.0.1`. Remote access should only occur through controlled, authenticated tunnels (e.g., Cloudflare Tunnel, Tailscale).
2. **Strict Host Header Validation**:
   Requests must match configured allowed hosts (e.g. `127.0.0.1`, `localhost`, `*.trycloudflare.com`). Unrecognized `Host` headers are rejected with `403 Forbidden` to prevent DNS rebinding attacks.
3. **API Key Authentication**:
   - Every request must provide a valid API key via header (`X-AgentPorter-Key` or legacy `X-M3-MCP-Key`).
   - Comparisons are performed in constant time using `hmac.compare_digest`.
   - Keys are stored in `~/.config/agentporter/secrets.env` with file permissions `0600`.
4. **Rate Limiting & Payload Ceiling**:
   - In-memory sliding window rate limiter (default: 120 requests/minute per client).
   - Maximum HTTP request payload size: 10 MB.

---

## 3. Filesystem & Path Traversal Safeguards

All tool operations accepting paths enforce strict validation:
- **Workspace Scoping**: All operations require an explicitly registered `workspace_id`.
- **Relative Path Enforcement**: Absolute paths (e.g. `/etc/shadow`, `/mnt/c/Windows`) are rejected.
- **Traversal Prevention**: Relative paths containing `..` or resolving outside the workspace root (via symlink resolution or `os.path.commonpath`) are blocked.
- **Sensitive Path Denylist**: Access to internal metadata or credentials within the workspace is rejected:
  - `.git/`
  - `.ssh/`
  - `.env` and `*.env`
  - `id_rsa`, `id_ed25519`, `*.pem`, `*.key`
  - `secrets.env`
- **Non-Destructive Deletion**: Deleting files moves them to a workspace-local `.trash/` timestamped folder rather than unlinking.

---

## 4. Git Operation Boundaries

- **Inspection Only**: Only read-only operations (`git_status`, `git_diff`, `git_log`, `git_show`) are exposed.
- **No Mutation**: `git commit`, `git push`, `git reset`, `git checkout` are not exposed via MCP tools.
- **Argument Sanitization**: Arguments such as commit refs are checked to prevent option injection (e.g., rejecting refs starting with `-`).

---

## 5. Reporting Security Vulnerabilities

If you discover a security vulnerability within AgentPorter, please do not open a public issue. Contact the repository maintainer directly or report it via GitHub Private Vulnerability Reporting.
