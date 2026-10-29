# Signed Git publication — internal candidate

`agentporter.git_pushes.ApprovedGitPushes` implements exact single-use approved
publication to one protected-policy HTTPS repository and branch. The current
source connects it to authenticated MCP/REST routes and the independent
owner-device review interface. It is not installed or independently accepted
on BCC. Synthetic-key loopback fixtures are not evidence of a real owner
credential or remote publication.

Preparation acquires shared synchronous capacity, revalidates owner remote
policy, holds the workspace mutation lease, discovers the current remote tip,
and generates a private immutable pack. The request binds canonical repository
path/device/inode, local HEAD/staged tree/branch, logical remote ID, exact URL,
remote branch/old/new object IDs, pack SHA256/length, and protected policy hash.
The host-only credential broker reads no repository remote configuration.

The fixed Git program runs offline in the existing supervised sandbox. Both
the worktree and canonical metadata are read-only; a private output directory
is its only extra writable mount. A sealed configuration hides repository
includes, hooks, credential helpers and pack configuration. The environment
disables lazy fetching, replace refs, grafts and interactive helpers. Shallow
histories are refused; an existing remote tip must exist locally as a commit
and be an ancestor of the selected local HEAD. Missing tips require a separately
authorized fetch implementation, not an implicit network fallback.
Ancestry is checked with Git's documented
[`merge-base --is-ancestor`](https://git-scm.com/docs/git-merge-base).

Git strictly checks objects and walks the selected commit's complete graph.
The output contains only those reachable objects, sorted before packing, with
fixed compression and no delta/object reuse. The graph has at most 100,000
objects. Output files and pack size are bounded; the sandbox's resource and
timeout limits still apply. SHA1 and SHA256 packs are supported. This uses
complete packs rather than excluding remote objects, so it never relies on
unapproved remote history for pack construction. Large histories outside
these bounds fail closed.
The pack options follow Git's
[`pack-objects` documentation](https://git-scm.com/docs/git-pack-objects).

Execution regenerates the request and pack under the same lease. Any changed
local state, remote tip, policy or payload invalidates the signature. Only a
valid independent single-use receipt permits durable intent creation. The
version-2 Git guard is fsynced before linking retained shared admission and
before any receive-pack request. Authority is revalidated immediately before
credential use. The transport rediscovers the expected old tip and the server
performs its atomic old-ID check. No force or deletion operation exists.

Success requires exact unpack/ref acknowledgment, a durable private success
receipt, and admission resolution before the guard is removed. An unconfirmed
publication retains the guard and capacity; no publication POST is retried.
If final guard removal fails after durable success and admission resolution,
recovery recognizes the already-resolved admission while retaining workspace
blocking until the owner acknowledges the guard.
No local tracking ref, index, worktree file, or commit is changed by
this backend. An owner change to local metadata cannot be overwritten by a
push.

`agentporter.git_push_recovery.recover_push` is an internal owner-maintenance
API, without MCP/REST or CLI exposure. It requires the actual BCC worker and
cgroup to be stopped/quiescent and obtains the exclusive supervisor and
workspace leases. It verifies private guard schema, canonical repository
identity, exact spent approval and durable admission binding (including the
crash window before binding), and current protected remote authority. It only
discovers the remote ref. Its report classifies the current ref as
`approved_tip`, `original_tip`, or `conflict`; these are current observations,
not claims about whether an earlier request ever ran. No pack is resent, no
remote ref is changed, and the receipt nonce is never restored.

Owner acknowledgment requires a fresh exact plan hash and a nonconflicting
observation. A durable recovery receipt precedes capacity resolution and guard
removal. A changed remote observation invalidates the prior review. A conflict
retains the guard and requires owner resolution; it cannot reset remote history.

Tests use synthetic signing keys and disposable local repositories. Actual
`git-http-backend` fixtures verify SHA1/SHA256 signed pushes and object integrity,
unchanged local metadata, and recovery after a simulated lost host-side result
following real loopback publication. Only the fixtures replace pinned HTTPS
with a loopback connection. Other tests exercise stale state/signatures,
unauthorized scope, graft-based ancestry manipulation, absent supervision,
uncertain outcomes, running-worker/stale-plan recovery denial, guard tampering,
and guard-before-admission failure. These fixtures do not prove actual TLS or
owner enrollment, public authenticated routing, or live BCC acceptance.

Remaining gates: a dedicated owner-invoked push recovery entry point using the
full protected catalog, immutable deployment, owner key/policy provisioning,
real owner-phone workflow, and independent frozen AP-01 through AP-06
acceptance. Pull eligibility remains disabled.
