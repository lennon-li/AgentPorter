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
- no host home, SSH keys, GitHub credential directory, SSH-agent socket,
  global Git configuration, Windows mounts, or Docker socket are mounted;
- read-only system runtimes, private environment, and synthetic `HOME=/tmp`;
- network namespaces are always unshared for generic execution. Both REST
  and MCP default offline; `network_access=true` is rejected without a trusted
  approval/egress broker, which is not implemented in this candidate;
- the top-level `.git` control directory/file is mounted read-only even if
  the workspace itself is writable. This does **not** prevent a writable
  sandbox process from creating nested repos or writing alternate Git files;
- `--die-with-parent`, so background helpers (dbus, git credential caches) are killed with the command instead of holding the run open;
- bounded synchronous output collected incrementally with a hard byte
  ceiling; overproducing processes are killed instead of buffered in full;
- asynchronous job output streamed through bounded pipes; each stream has a
  strict byte budget. Exhaustion or timeout kills the child's process group,
  including ordinary descendants retaining inherited output descriptors.
  Detached host-user descendants can still escape a process-group boundary;
  separate OS identity / cgroup containment remains required.

AgentPorter does not yet impose cgroup CPU/memory quotas. Treat time and output
limits as denial-of-service mitigation, not complete resource accounting.

### Worker delegation: candidate fails closed; confined launcher pending

The seven named identities remain discoverable even when a CLI is installed.
**Installed/available is different from authorized/delegatable**; the
candidate reports `delegatable=false` and
`confinement_status=blocked_pending_os_confinement` for every worker. An
attempt to `dispatch_agent`, whether `read_only=true` or a requested write,
raises `PermissionError` before CLI launch. The broker has no raw-launcher
fallback, and `JobManager.start_raw_job(agent=...)` refuses host-user agent
processes. Only a future *trusted, kernel-confined* agent launch path may
restore delegation.

This is a deliberate temporary **availability regression** relative to the
running release; do not deploy it as a feature-complete seven-agent service.
It fixes the immediate unsafe host worker execution path by disabling it,
rather than solving the final OS isolation and cloud-model-egress problem.
A confined launcher must provide strictly scoped filesystem writes,
credential isolation, and model-only egress for each named runtime without
switching any profile/model/provider. Existing CLI-specific read-only
switches are still defenses in depth, not a substitute for isolation.
The user's voice and ChatGPT client consent do not mint a server-trusted
approval receipt for commits/pushes.

See the [authorization design](docs/action-authorization-design.md) and
[54-action classification](docs/agent-roster-action-policy.md) for the
pending approval issuer, publisher service, and negative acceptance tests.

## 2. Ingress security

AgentPorter defaults to:

- bind address `127.0.0.1`;
- API-key authentication using `X-AgentPorter-Key`;
- only localhost Host headers;
- constant-time key comparison;
- per-client rate limiting;
- request-body limits: REST counts declared and actual ASGI bytes; MCP
  uses the SDK's native pre-handler 413 enforcement, capped at the lower of
  the configured limit and its 4 MiB default (including streamed bodies).

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
- Git operations and inspection;
- artifact access;
- worker-agent dispatch;
- exact loopback HTTP ports.

`writable: false` controls file mutation and direct sandbox mounts.
Git fetch mutates FETCH_HEAD, refs and objects and is denied in a read-only
workspace; pull uses fast-forward-only mode to prevent implicit merge commits.
Worker agents require an adapter capable of enforcing read-only mode.

## 5. Loopback HTTP

`local_http_request` executes from the host-side AgentPorter process and can
reach loopback services. It is therefore a separate host-level trust boundary,
not sandboxed execution.

It is disabled by default for each workspace. A request is allowed only when
the destination port appears in that workspace's `local_http_ports` list.
Redirect following is disabled.

## 6. Git publication and independent approval boundary

Direct Git inspection includes status, diff, log, show and branch listing;
additional tools include fetch, fast-forward-only pull, staging and checkout.
The dedicated `git_commit` and `git_push` endpoints return permission
denied (REST HTTP 403) until independently verified owner approval receipts
are implemented. Delegated workers also reject caller-supplied commit/push
flags without a trusted receipt.

**These dedicated locks are not a global publication guarantee.**
Arbitrary writable execution (especially REST's current networking default),
host-user worker CLIs, local HTTP side effects and other external capabilities
can still mutate Git metadata or publish without hitting the locked direct Git
tools. Writable execution can also access host SSH/GitHub credentials when
networking is enabled; a read-only credential mount does not prevent disclosure.
The API key authenticates the client but is not a signed, operation-specific
approval from the owner. Client-side ChatGPT **Always ask** does not prove an
operator approval to AgentPorter.

This boundary is a pending architectural risk, not resolved by the seven-agent
roster change. Before claiming comprehensive action-policy enforcement, add a
server-verified, short-lived approval protocol and isolate unrestricted
execution/worker processes from Git and publication credentials. Review
the complete [action authorization matrix](docs/agent-roster-action-policy.md).

Repository-local Git configuration still exists on the host. Use these
operations only for trusted, registered workspaces.

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
