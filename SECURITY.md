# Security Architecture & Threat Model

> Status: early alpha / active dogfooding (using the project in real workflows to discover defects before wider release).
> Scope: Linux and WSL2.

AgentPorter exposes local development capabilities to MCP clients, so security
boundaries are part of the product contract.

## 1. Direct execution and delegated workers

Direct commands and configured workers use Bubblewrap confinement with private
temporary storage, scrubbed environments and bounded output. Generic commands
stay offline. Independently configured fixed-function egress admits only its
reviewed destinations and operations. Host SSH, publication and signing
credentials are not mounted into generic commands.

The shared-policy profile defaults delegation and direct execution to read-only.
Writable requests require signed, expiring task authority and execute against a
private copy-on-write view. Publication validates the write set after producer
exit and verified cleanup. Protected paths and Git metadata remain immutable;
unapproved deletion, unsafe links and concurrent changes refuse publication.
Whole-workspace size does not consume the per-job changed-output budget.

Configured delegated runtimes also require a verified launcher and explicit
resource controls. Unsupported runtimes fail closed instead of falling back to
host-user subprocesses. CLI read-only flags supplement the operating-system
boundary; they do not replace it. Registration, runtime eligibility, provider
authentication and provider quota are separate checks. Never substitute an
account, provider or model when a selected worker fails.

The view helper is fixed-purpose and separate from model execution. Its merged
view must be visible in the launcher's mount namespace; a trusted bootstrap
checks the actual mounted identity and closes inherited setup descriptors before
any model code. The worker retains NoNewPrivileges. Cgroup enforcement depends
on explicit operator-provisioned delegation and limits; it is not implied by
installing the Python package.

See [shared workspace policy](docs/shared-workspace-policy.md) and
[request authorization](docs/action-authorization-design.md) for scope and limits.

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

`writable: false` denies ordinary file edits. In the shared profile, a writable
workspace is only an eligibility ceiling: execution still defaults to read-only,
and an edit-capable task needs separate verified approval. Specialized remote or
scientific capabilities never inherit ordinary workspace defaults.

The shared profile has a dedicated bounded public-HTTPS Git-fetch backend.
Fetching updates only approved repository metadata; it grants no generic write,
publication or credential access. Unsupported or private-authentication remotes
fail closed. Legacy fetch and all pull requests retain their stricter backend
and authorization requirements.

## 5. Loopback HTTP

`local_http_request` executes from the host-side AgentPorter process and can
reach loopback services. It is therefore a separate host-level trust boundary,
not sandboxed execution.

It is disabled by default for each workspace. A request is allowed only when
the destination port appears in that workspace's `local_http_ports` list.
Redirect following is disabled.

## 6. Git publication and independent approval

Git inspection is distinct from edits, metadata mutation and publication.
Dedicated commit/push endpoints and delegated commit/push flags remain locked
until a separately verified publisher exists. An edit receipt cannot authorize
publication. API authentication and client-side confirmation cannot mint a
trusted task receipt or unlock an unavailable backend.

The shared boundary verifies signed task arguments, expiry, workspace/root,
worker and permitted effects. Identical approved retries recover one job rather
than launching twice. Signing keys live outside model-accessible workspaces and
service credentials. Both relay ends independently verify authority.

Publication checks prevent unsafe filesystem effects; they do not establish the
semantic correctness of an approved edit. Review output diffs. Non-cooperating
host writers must remain quiescent during publication, and multi-file publication
is not crash-atomic. Broader trusted confirmation UIs and a dedicated Git
publisher remain future work.

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
