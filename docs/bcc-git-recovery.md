# BCC approved Git commit recovery — candidate procedure

The candidate module `agentporter.git_commit_recovery` reconciles a retained
`.git-pending.json` guard from the exact owner-approved commit backend. It has
no MCP/REST entry point. It does not create or retry commits, change repository
files or history, delete Git locks, or restore consumed approval nonces.
This module has not been installed or exercised in a real offline worker
maintenance window. Use it only from the audited immutable release after the
owner has installed that release and its protected backend policy.

Before inspection, the owner must stop `agentporter-bcc-worker.service`. The
module verifies the stopped service, empty cgroup, and exclusive supervisor
lock, and retains the shared workspace mutation lease. Run as the non-root
owner of the private backend state and claim ledger. The state directory and
transaction directory must be private to that identity. A later separately
installed Git service must also have its lifetime covered by maintenance
before this procedure can certify that deployment.

Using that immutable release's Python, run:

```text
python -I -m agentporter.git_commit_recovery \
  --state-dir STATE \
  --workspace WORKSPACE \
  --workspace-id ID \
  --ledger LEDGER \
  --public-key VERIFICATION_KEY
```

`STATE` is the backend state directory containing `workspace-transactions`.
`WORKSPACE` and `ID` must match the guarded registered repository exactly.
`LEDGER` is the existing protected SQLite claim ledger; recovery never creates
a missing ledger. `VERIFICATION_KEY` is its protected raw 32-byte Ed25519
public key, never a signing key. No provider credentials are required.

Inspect the JSON plan and retain it in owner-private storage. It identifies the
guard/request digests, consumed nonce, current branch/HEAD/staged tree, expected
approved commit identity, unresolved metadata locks, and `plan_sha256`.
Expected commit identity is derived in private scratch storage using Git's
identity formatting and the exact approved message bytes, including trailing
newlines. The actual decompressed commit bytes must also match before the
approved commit is acknowledged. SHA1/SHA256, initial commits, and UTF-8 identities/branch names are
supported by the candidate implementation.

The observation is one of:

- `approved_commit_at_head`: the approved commit is the current branch tip.
- `original_head`: the branch currently has its original approved HEAD. This
  does not prove the operation never ran; an owner could have reset history.
- `conflict`: branch/history differs, or Git lock files remain unresolved.

Recovery preserves owner changes. It refuses unsupported metadata layouts and
does not automatically delete stale or potentially active Git lock files. A
conflicting plan cannot clear the guard. Resolve such cases through explicit
owner investigation, then inspect again; do not delete the guard to bypass the
refusal.

For a nonconflicting reviewed plan, repeat the invocation with:

```text
--apply --expect-plan-sha256 REVIEWED_HASH
```

The command re-inspects and requires the exact current plan hash, verifies the
nonce/request pair is still present in the consumed ledger, and writes a
durable receipt under `STATE/git-recovery-receipts` before clearing only this
Git guard. For an observed approved commit it also persists ref/reflog contents
and relevant metadata directory entries before that clearance. A durability
failure retains the guard. Version-2 guards also bind a private Git admission
token. Recovery validates its database linkage, resolves only that admission,
and retains the resolved binding record so interrupted final guard clearance
can be retried. A durable guard preceding database binding may be observed as
`unbound`; Git execution cannot precede that binding. It preserves unrelated
guards and job admissions. It never makes
the old receipt reusable. A new operation requires a freshly signed request.
Retain the receipt, restart the audited worker release through the owner
service manager, and verify a bounded subsequent job.

Private corruption, missing claims, changed roots, conflicting history,
unresolved locks, missing objects, and failed service/quiescence checks are
refusals rather than automatic repairs. Public API admission integration and
actual offline maintenance verification remain required before production
activation.
