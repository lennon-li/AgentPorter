# Owner-approved Git fetch — candidate

`agentporter.git_fetches.ApprovedGitFetches` fetches exactly one protected branch
into its remote-tracking ref. MCP and REST expose preparation and execution only
when the owner remote policy is installed. This source has native SHA1/SHA256
coverage but is not installed or independently accepted on BCC.

A public-client policy must grant the selected workspace the separate
`git_fetch` operation scope. `git_read` and `git_write` do not grant fetch
invocation. That scope only permits the client to request the operation; it does
not bypass the owner-installed remote policy or its single-use signature.

The protected policy is owner-installed as `git-remote-policy.json`, with a
public verification key, existing private claim ledger, and exact grant fields.
A grant may authorize only `fetch` or `push` for a specific workspace, logical
remote ID, HTTPS repository URL, and `refs/heads/...` ref. `credential_file` is
owner-selected or null. Repository remote configuration and caller-supplied
URLs/credentials are ignored.

Preparation reports a canonical request binding repository path/device/inode,
local HEAD/index tree/branch, remote identity and URL, source branch and
advertised object, exact `refs/remotes/<remote-id>/<branch>` target and prior
tracking tip, pack SHA256/size, and owner-policy fingerprint. The independent
owner device displays these fields and signs only the exact request. REST and
MCP reject caller-selected approval authority.

Execution consumes the single-use receipt, rediscovers the protected branch,
regenerates and hashes the bounded pack, and checks the current local state.
A supervised offline Bubblewrap phase imports the pack into a private quarantine
object database, runs strict index and connectivity checks, then promotes only
the resulting Git pack and index without overwriting existing objects. A second
supervised offline phase checks the state again and compare-and-swaps only the
exact tracking ref. It does not move `HEAD`, edit the index or worktree, merge,
rebase, or update the current branch. Pull remains locked.

An interrupted operation retains a durable workspace guard and shared
admission. `python -m agentporter.git_fetch_recovery` is an owner-only CLI. With
the worker stopped, it reports the current tracking ref as `approved_tip`,
`original_tip`, or `conflict`. The owner reviews the plan hash and explicitly
applies it. Recovery never contacts the remote, retries a fetch, changes refs,
or deletes objects; it records a durable receipt before clearing the guard.

Native disposable-repository tests cover SHA1 and SHA256, pre-index and
post-ref-update interruption, tracking-ref-only behavior, pack promotion
without overwrite, and owner recovery. They do not establish owner key
provisioning, a deployed policy, TLS to a real host, or frozen live AP-01–AP-06
acceptance.
