# Shared workspace policy and private edits

The shared-policy profile uses a protected, operator-owned policy to compile
workspace capabilities, public-client scopes and receiving-worker admission.
Gateway and worker references must identify the same policy. Ordinary defaults
can apply to future registrations, while explicit overrides narrow particular
workspaces. Protected control paths remain inaccessible to model jobs.

This is an optional profile. Legacy workspace configuration does not silently
inherit writable delegation, network access or specialized infrastructure grants.

## Request authority

Delegation and direct execution default to read-only. A writable task requires an
Ed25519-signed, expiring approval bound to the workspace ID and canonical root,
action, worker where applicable, exact normalized arguments and allowed effects.
The private signing key belongs to a separate trusted operator workflow; model
code and public API clients receive no signing capability.

Both relay boundaries verify authority. Missing, expired, forged or altered
approvals fail closed. A stable request identity binds approved retries to the
original job, including after ambiguous delivery. A failed job is not retried as
a new job merely by resubmitting the same request identity.

Edit authorization does not grant deletion or publication. Destructive typed
operations require their own authorization. Git commit and push remain locked
until a separately verified publisher is implemented. Conversational approval,
an API key and caller-supplied flags cannot unlock those backends.

## Copy-on-write execution

A fixed-purpose helper creates a private FUSE overlay and leases its merged
directory to the launcher. The sandbox receives that view, approved runtimes and
the minimum provider-specific material. It cannot reach the helper socket,
backing directories, host descriptors, signing key or service configuration.

The helper and launcher must share a mount namespace: Bubblewrap canonicalizes
bind sources, including descriptor paths. A view hidden in another namespace
would resolve to its empty backing directory. Before model code runs, a trusted
bootstrap checks the mounted device and inode against the expected view, then
closes inherited non-stdio descriptors. The worker retains NoNewPrivileges and
its separate Bubblewrap isolation.

Workspace size is independent of the changed-output budget. A small edit can
operate on a workspace containing large data files without copying them all.
Changed files and bytes remain bounded. Excess output or helper failure refuses
publication; cancellation discards the private view.

After the producer exits and cleanup is verified, publication validates only the
write set. It rejects protected paths, Git metadata changes, unsafe links,
privileged modes, unapproved deletion and concurrent source changes. External or
inert Git control files stay masked and read-only while ordinary code remains
editable. Metadata path pinning retains only final handles, so deep paths do not
exhaust a descriptor for every ancestor. Human collaborator access and existing
users' effective ACL permissions are preserved.

Publication is not a crash-atomic multi-file transaction. Operators must keep
non-cooperating host writers quiescent during publication. Approval grants a
workspace-scoped edit capability; it does not prove that every semantic change
the model makes is desirable. Review the resulting diff.

## Git transport and specialized access

The shared profile provides a fixed-purpose public-HTTPS Git-fetch transport.
It pins allowed transport properties, validates fetched objects in an isolated
temporary repository, and publishes only the bounded remote-tracking metadata.
It does not execute the original repository's hooks or expose host credentials.
Private-authentication and unsupported transports fail closed. Generic command
networking remains disabled unless a separate fixed-function policy admits it.

Specialized scientific or remote-infrastructure grants remain explicit. A worker
sharing the gateway's registrations does not inherit public operations for
gateway-only backends. A Git-fetch grant does not grant pull, commit or push.

## Operator workflow

Reference preparation, migration, installation, approval-issuance and worker
validation scripts live under `scripts/`. Review their service identities, paths,
workspace assumptions and dependency provenance for the intended deployment.
They are not an unattended installer for arbitrary machines.

The installer plans configuration and ACL changes while production is running,
executes candidate runtimes and scope compilation under their service identities
before shutdown, verifies real worker and human writes, and restores previous
controls and releases if activation fails. Runtime repairs preserve an existing
shared policy and approval keys, and accept only identical trusted helper units.
Recovery journals are unique per attempt and remain private.

Source tests cover real FUSE/Bubblewrap edits, large workspaces, protected Git
metadata, descriptor closure and budgets, unsafe outputs, cancellation,
concurrent changes, signed approval failures, retry identity, policy migration
and ACL rollback. Those tests do not certify another installation's service
state, provider credentials or quota. Provider failures must be reported without
silently substituting another account, runtime or model.

Keep live workspace registries, hostnames, addresses, credentials, signed task
tokens, job output, recovery snapshots and account usage in private operator
storage. Public reports should contain only generic behavior and sanitized
verification summaries.
