# BCC owner-approved commit API — candidate

The candidate supports exact owner-approved commits through the shared MCP
`git_commit` tool and REST `/api/v1/workspaces/{workspace_id}/git/commit` route.
This source has not been installed or certified on BCC. Exact owner-approved
push and fetch are implemented in separate backends; pull remains locked. See
`docs/bcc-git-approved-push.md` and `docs/bcc-approved-git-fetch.md`.

Activation requires an owner-installed `git-commit-policy.json` in the gateway
configuration directory, an existing private claim ledger, transaction-enabled
workspace execution, and verified resource supervision. No policy means commits
remain locked, including preparation. A permissive action-mode setting alone
cannot enable commits. An owner `LOCKED` override still denies them.

Policy template; replace all placeholders through the owner installation path:

```json
{
  "version": 1,
  "author_name": "OWNER_NAME",
  "author_email": "OWNER_EMAIL",
  "verification_key": "RAW_ED25519_PUBLIC_KEY_AS_64_LOWERCASE_HEX_CHARACTERS",
  "ledger_path": "/var/lib/agentporter-bcc-worker/owner-git/claims.db",
  "workspaces": ["bcc-acceptance"]
}
```

The signing key stays outside AgentPorter and delegated workers. The policy
contains only its public verification key. The policy must be a trusted
single-link regular file with trusted directory ancestors: private mode 0600
under the service owner, or an immutable non-writable root-owned control file.
The loader rejects symlinks, hard links, writable policy files, duplicate JSON
keys, wildcard workspace IDs, unknown fields, unregistered or read-only Git
workspaces, and noncanonical ledger paths. It never initializes a missing
ledger. The configuration, ledger, gateway state, and executing package must
remain outside every exposed workspace.

Policy data and registered repository filesystem identities are pinned at
startup. Each request rechecks the policy digest, workspace identity, and
protected-path separation. Changed or removed policy revokes this loaded
authority; an audited restart is required to activate new policy.

In a hardened public-client profile, add the explicit `git_commit` operation
scope for each selected workspace. Existing `git_write` scope permits staging
and checkout, and does not grant commit access. The independent signature is
still required even with `git_commit` scope. Public delegation's `allow_commit`
and `allow_push` flags remain unable to mint approval or enable worker-side
publication.

After scoped edits, tests, staging, and diff review:

1. Call `git_commit` with the exact message and `prepare_only=true`. Preparation
   does not commit or issue a signature. Its proposal contains `request` and
   `request_sha256`, including the exact timestamp and protected author identity.
   REST retains the existing string response type; decode its JSON string to
   obtain the proposal object.
2. The independent owner issuer reviews that exact request and signs it with
   the matching external private key using the documented Ed25519 protocol.
3. Submit the same message, `approval_timestamp` from the proposal's parameters,
   and `approval_receipt`. Keep `all_files=false`; implicit staging is refused.
   The response is the resulting commit object ID.

Do not supply a verification key, ledger path, policy path, or workspace path
in a commit request. REST rejects these extra fields; MCP exposes no authority
selection parameters. Missing, mismatched, altered, expired, or replayed
receipts fail closed. An operation failure cannot restore a spent receipt.
The static owner-device interface and native browser signing tests are now
implemented; see `docs/bcc-owner-approval.md`. Independent hosting and real
device/public-key enrollment remain unfinished. This API is not proof of a
terminal-free production owner workflow.

Preparation and execution share gateway capacity with commands and agents.
An operation's durable Git guard records its private admission token. That
guard is persisted before the database binding and before any Git mutation.
Startup recovery preserves active bound admissions. Successful cleanup and a
durable commit receipt permit capacity release before final guard clearance;
uncertain outcomes keep their guard and capacity. Resolved binding records
remain available so interrupted final clearance can be retried safely.

Owner Git recovery verifies the exact guard/request/admission linkage, writes
a durable recovery receipt, resolves only that admission, and then clears the
guard. A crash before database binding is separately observable as `unbound`;
no Git execution can precede the binding. Other guards and admissions are
preserved. See `docs/bcc-git-recovery.md` for the offline procedure.

Native authenticated MCP/REST tests use disposable repositories, synthetic
owner keys, and recording resource providers. They establish source behavior,
not actual service installation, live cgroup budgets, cross-owner operation,
provider availability, issuer setup, or AP-01 through AP-06 acceptance.
