# AgentPorter Architecture

AgentPorter is a local-first MCP gateway between AI clients and controlled
development capabilities.

```text
MCP client
   |
   v
HTTP security boundary
   |
   +--> workspace file/search tools
   +--> bounded Git/artifact tools
   +--> direct execution --> Bubblewrap sandbox
   +--> loopback HTTP --> explicit per-workspace port allowlist
   +--> worker broker --> host-user CLI adapter
```

## Workspaces

Clients never supply arbitrary host roots. They select a registered
`workspace_id`. Each workspace has a local path plus independent capability
flags for execution, Git, artifacts, worker dispatch, and loopback ports.
`writable` controls file mutation and the direct sandbox mount mode.

File paths are project-relative and validated against traversal, symlink escape,
and sensitive-path rules. Text search applies the same disclosure boundary.

## Direct execution

`exec_run` and `exec_start` use Bubblewrap with:

- no network;
- cleared environment;
- private `/tmp`;
- omitted host home/credential locations;
- workspace mounted RW or RO;
- bounded time/output.

Async jobs use a private SQLite/log state directory and enforce per-stream log
limits.

## Worker adapters

Worker CLIs are intentionally separate from direct execution. They run as the
host user so they can access their provider credentials and network.

Adapters declare which controls they can enforce:

- read-only execution;
- model override;
- reasoning override.

The broker rejects a request when the requested security/control property
cannot actually be enforced. Personal aliases and preferred model routing are
local deployment concerns, not package defaults.

## Runtime provenance

Configured routing, explicit requested overrides, and verified actual runtime
model are distinct fields. Worker stdout/stderr is untrusted and cannot prove
which model executed a job. Until an adapter has a trusted provenance channel,
`actual_model` is `unknown`.

## Package/local boundary

Generic source lives in this repository. Machine-specific workspace
registrations, credentials, runtime state, provider routing, and client-specific
deployment policy live outside the package under local configuration/state or a
separate private deployment repository.
