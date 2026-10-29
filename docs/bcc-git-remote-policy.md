# Owner remote authority — internal candidate

`agentporter.git_remote_policy.load_owner_git_remotes` reads only the fixed
`git-remote-policy.json` in the protected operator configuration directory.
Nothing loads it in the public server yet. Installing this file does not
enable push, fetch, or pull. Do not install authority as a substitute for the
remaining signed-execution and outcome-recovery work.

The strict version-1 document has this shape (synthetic values):

```json
{
  "version": 1,
  "verification_key": "<64 lowercase hex characters: owner Ed25519 public key>",
  "ledger_path": "/protected/service-state/git-approvals.sqlite",
  "grants": [{
    "workspace_id": "disposable-repo",
    "remote_id": "origin",
    "url": "https://example.com/owner/disposable.git",
    "ref": "refs/heads/owner-reviewed-feature",
    "operations": ["fetch", "push"],
    "credential_file": "/protected/credentials/git-token",
    "username": "x-access-token"
  }]
}
```

The key placeholder is explanatory, not valid configuration. Use the public
key from the independent owner issuer, never an agent-generated signing key.
The single-use ledger must already exist with the verifier's private ownership
and schema. Loading authority never creates a missing ledger or reads a token.
The token path can be null for a public remote. Token validation and reading
occur only in the protected broker at actual request time.

Policy files require trusted ancestors, one regular file with no aliases, and
either current-service-owner mode 0600 or a root-owned file without group/other
write permissions. Symlinks, duplicate JSON fields, unknown fields, implicit
wildcards, noncanonical paths, unqualified refs, tags, deletion, force/pull
operations, and caller-supplied authority are not accepted. A maximum of 128
explicit grants is supported. Each workspace/remote/ref tuple is unique;
multiple branches for one workspace/remote ID must share the same exact URL,
credential path, and username. See the transport document for URL and protocol
bounds.

Each authorization rechecks the complete current workspace catalog for
overlap with policy, ledger, credential, service state, and package authority.
It rejects changed policy bytes, changed registration permissions, and changed
canonical repository path/device/inode. The broker receives all current
workspace roots. A new registration that exposes authority revokes use even
when it is unrelated to the selected grant. No repository Git configuration,
environment credential helper, or tool argument can select an alternative
remote or credential. A changed policy requires a separately audited restart;
it does not silently expand a running backend's authority.

This policy determines eligibility, not approval of a particular operation.
The internal [signed push backend](bcc-git-approved-push.md) now constructs the
exact request while holding the workspace lease and implements supervised pack
generation, durable publication intent, and owner outcome reconciliation.
Public wiring and owner-device push signing remain pending. Any network backend
must construct the exact request while holding the
workspace lease, bind its local state, remote old/new IDs, immutable pack and
selected remote authority to an independently signed single-use receipt,
validate graph/fast-forward semantics, retain admission and durable outcome
state, and reconcile uncertain publications. Public API wiring and actual
installed/live acceptance remain pending. Unit/native ownership tests of this
loader are not evidence that an approved network operation has run.
