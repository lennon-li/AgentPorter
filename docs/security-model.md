# AgentPorter Security Model & Threat Matrix

This document provides the security analysis and threat mitigation matrix for AgentPorter.

---

## 1. Threat Matrix

| Threat Category | Potential Attack Vector | AgentPorter Mitigation |
| :--- | :--- | :--- |
| **Network Ingress** | DNS rebinding from malicious websites | Strict `Host` header validation against `allowed_hosts`. |
| **Authentication** | Brute force or timing attacks on API key | High-entropy random key (32 bytes urlsafe), constant-time `hmac.compare_digest`, sliding-window rate limiting. |
| **Filesystem Escape** | Path traversal sequences (`../../etc/passwd`), absolute paths (`/mnt/c`) | Strict rejection of absolute paths; canonical path resolution ensuring target starts with workspace root; blocking `..`. |
| **Credential Theft** | Reading SSH keys, environment files, or git tokens in workspace | Hardcoded block on `.git`, `.ssh`, `.env`, `id_rsa`, `id_ed25519`, `secrets.env`. |
| **Malicious Code Execution** | Reverse shell, outbound network socket in Python/R/bash | Linux Bubblewrap sandbox with `--unshare-net` (network completely unreachable). |
| **Environment Leakage** | Reading parent process environment variables containing API keys | Bubblewrap `--clearenv` discards entire environment; sets minimal synthetic `PATH`, `HOME=/tmp`, `USER=sandbox`. |
| **Host System Access** | Accessing host root filesystem, Docker socket, or Windows drives under WSL | Only system runtime libraries (`/usr`, `/lib`, `/bin`) are mounted read-only. `/home`, `/mnt/c`, `/var/run/docker.sock` are excluded. |
| **Denial of Service** | Oversized payloads or runaway background jobs | 10 MB payload ceiling; per-client rate limiting; process group timeout and `job_cancel` killing child subtrees. |
| **Worker Agent Over-Reach** | Unintended mutations by dispatched worker CLIs | Explicit control packets (`Permission Level: 1`, `Step budget`, `READ-ONLY` if workspace non-writable); preflight git dirty checks. |

---

## 2. In-Depth Boundary Analysis: Sandbox vs. Worker Agents

### The Direct Execution Boundary
Commands executed through `exec_run` and `exec_start` run directly inside an OS-level Linux namespace sandbox managed by Bubblewrap (`bwrap`).

1. **Kernel Enforcement**: User namespaces, mount namespaces, IPC namespaces, and network namespaces are unshared.
2. **Network Isolation**: Direct execution has zero network access. Any attempt to resolve DNS or establish TCP/UDP connections fails with `ENETUNREACH`.
3. **Synthetic Identity**: The process executes as user `sandbox` (UID 1000) using a synthetic in-memory `/etc/passwd` and `/etc/group`.

### The Worker Agent Delegation Boundary
Dispatched AI agents (e.g. OpenAI Codex, Anthropic Claude Code) are **not** run inside the Bubblewrap sandbox.

**Why?**
Modern AI CLI agents must:
- Connect to internet endpoints (e.g. `api.openai.com`, `api.anthropic.com`, Google Vertex AI).
- Read their user authentication credentials stored in `~/.codex/`, `~/.claude/`, etc.

**Implications**:
- Dispatched worker agents execute with the host user's privileges.
- Bounding is enforced at the application layer via:
  - Working directory (`cwd`) scoping.
  - Formatted control blocks in the prompt (`Authorization`, `Step budget`, `Scope`).
  - Preflight Git checks and execution logging.
- Users should only dispatch worker agents to workspaces they trust and monitor agent output.
