# BCC Git owner approval protocol — candidate

This is the unfinished authorization component for AP-03 in the frozen BCC
production acceptance contract. It does not enable commit, push, fetch, or pull.
Those shared MCP/REST tools still refuse execution.

`agentporter.git_approvals` defines a canonical request and an Ed25519 receipt.
The request binds one workspace, the canonical repository path and filesystem
identity, full HEAD and index-tree object IDs, an explicit branch, the operation,
and all operation parameters. A signature binds its digest, protocol audience,
nonce, issue time, and expiry. Receipts last at most five minutes. The verifier
rejects changed requests, malformed or duplicate JSON fields, unrelated keys,
invalid signatures, future or expired receipts, and replay. A transactional
SQLite nonce insertion permits only one concurrent claim.

The owner signer must operate outside delegated workers. Neither signing keys
nor a signing endpoint may be exposed through a workspace, agent profile, or
generic execution. The future backend must obtain its verification key and
ledger location from protected operator policy; callers cannot select them.
The verifier's operator identity must be separate from delegated execution.
Filesystem checks do not protect against a malicious process with that same
operator identity or root access.

The ledger uses a private operator-owned directory and a private, single-link
regular file. Each claim rechecks the ancestor chain, parent identity and
privacy, and ledger identity. Existing SQLite journal/WAL/shared-memory files
must also be private, operator-owned, single-link regular files. Unexpected
sidecars are refused without deleting or repairing owner data. Initialization
checks these conditions before opening SQLite.

`agentporter.git_approval_state.locked_git_request` now holds the shared
workspace mutation lease while inspecting the actual repository in the
read-only, network-isolated sandbox. It binds the root filesystem identity,
HEAD, branch, and staged tree. Tree construction uses a private scratch Git
directory and a copied index, leaving canonical objects and index untouched.
SHA1, SHA256, unborn repositories, and split indexes are covered by native
tests. Index copies share a 64 MiB budget; more than 128 shared indexes are
refused. External Git directories and linked worktrees are explicitly refused
by this initial inspector. This limitation must be resolved or represented in
the final supported-workspace policy before enrollment.
Missing staged blob objects and missing/non-commit HEAD objects are refused.
HEAD object type is inspected through the scratch repository's clean
configuration and read-only alternate object store, avoiding lazy fetches or
repository-defined commands.

`approved_git_request` consumes the owner signature against this captured
request and retains the same lease through its context. It does not execute
Git. A changed staged tree cannot consume the original approval, replay is
rejected, and failure after a claim leaves the receipt spent. Expiry is checked
again after acquiring SQLite's write lock so waiting cannot admit a receipt
that expired before the claim. Pending workspace recovery prevents inspection.

Read-only inspection uses the existing bounded command primitive directly,
avoiding recursive transaction-lock acquisition; configured resource
supervision and verified process cleanup remain in that path. Fixed Git
inspection commands disable fsmonitor and hooks; tree construction uses clean
configuration without lazy fetching. No arbitrary caller command runs inside
the authorization context.

`agentporter.git_commits.ApprovedGitCommits` now implements an internal approved
commit operation. Protected backend policy supplies its registry, sandbox,
verifier, author name, and author email. Preparation binds those identities,
the exact message and timestamp, and actual staged repository state. Execution
requires a supervised transaction-enabled runtime and a matching unspent owner
receipt. It supports commits on explicit local branches, including initial
commits and SHA256 repositories; detached HEAD is refused by this initial
backend. It does not stage unstaged work or provide an all-files override.

The backend pins repository and metadata descriptors and inspects metadata
before granting writes. Symlinks, hard links, special files, nested mount
boundaries, active lock files, external object alternates, common directories,
and reftable storage are refused. Metadata inspection has a one-million-entry,
128-level, 30-second budget. Ordinary workspace files stay read-only. Only
`.git` is mounted writable, with its original config hidden behind sealed clean
configuration. Hooks, filters, signing programs, transport configuration,
global/system config, lazy fetching, and replacement objects cannot extend the
approved operation. Host mount descriptors are closed before the fixed worker
script runs; no arbitrary worker command receives this metadata access.

Inside that sandbox the fixed script revalidates approved HEAD/branch/tree,
writes exactly the approved tree/parent/message/identities/timestamp with
`commit-tree`, and compare-and-swaps the approved branch with `update-ref`.
Git syncs object files; the script syncs ref/reflog contents, their parent
directories, and loose-object directories before reporting success. A durable
private success receipt precedes clearing the durable Git-operation guard.
Failures after launch, ambiguous outcomes, receipt-storage errors, and resource
cleanup uncertainty retain the guard. Jobs, file/Git mutations, and state
inspection refuse a workspace with this guard, including after restart.
Workspace transaction recovery retains unbound admissions while any unresolved
Git guard exists.

The backend is now available through the shared commit tool only when the
owner-installed protected policy loads successfully, with durable gateway
admission and explicit public-client commit scope where public policy is
enabled. Missing policy preserves default LOCKED behavior. See
`docs/bcc-approved-git-api.md`; this source has not been installed on BCC.
Git-specific owner
recovery is implemented in `agentporter.git_commit_recovery`, with the
candidate procedure in `docs/bcc-git-recovery.md`. It requires stopped-service
maintenance, a matching consumed ledger claim, and an exact reviewed plan hash.
It only acknowledges an observed original HEAD or the exact approved commit
at HEAD; it never retries the operation or restores its receipt. Conflicting
history and unresolved Git locks retain the guard. Do not manually delete a
`.git-pending.json` guard or use workspace-file recovery to clear it. Owner
signer provisioning, protected service policy installation, real
offline recovery verification, and authenticated live API acceptance remain deployment
blockers. Native tests use synthetic owner signatures and
recording resource providers; they do not prove installed-worker cgroup or
provider acceptance.

Remaining execution integration:

1. Instantiate the inspection/consumption context only from protected backend
   policy. Never trust a caller-supplied request as evidence of the repository's
   current state. Actual execution must use pinned repository descriptors and
   revalidate applicable state before canonical metadata publication.
2. Verify and durably consume the receipt against that expected request before
   the exact approved operation. A consumed receipt remains spent on failure;
   retry requires a new reviewed request and receipt.
3. Keep repository-defined hooks, filters, helpers, configuration includes,
   transports, and credentials from extending the granted operation. Receipt
   verification alone does not make a generic metadata-writable shell safe.
4. Implement scoped transport and credentials for network Git operations.
   Preserve the current network denial until that backend exists.
5. Connect the protected backend to the shared tool boundary, then verify
   absence/mismatch/replay denials through both MCP and REST. Exercise the
   actual approved workflow and bypass negatives in an isolated repository.

Production remains on HOLD until the running audited release satisfies AP-01
through AP-06. Unit receipt verification is evidence for this component only.
