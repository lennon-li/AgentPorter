# Operator-verifiable action authorization (next implementation phase)

Status: **partial fail-closed implementation, not approved for deployment**. Candidate now blocks host-user delegated launches pending a kernel-enforced confined launcher, rejects all generic networked command execution, removes host SSH/GitHub credential binds, and makes repository root .git metadata read-only in generic Bubblewrap execution. Independent approval receipts, model egress broker, and complete OS isolation are NOT implemented.

Original rollout plan: design specification, not implemented. The seven-agent registry and the 53-operation policy catalog are implemented in the current release candidate; only direct Git commit/push and existing adapter/workspace controls are additionally restricted. Do not claim full voice-granted privileges.

## Goal

A user can say “Jax, edit Qman” and later “Commit and push the reviewed changes”, while AgentPorter itself—not ChatGPT prose or an agent instruction—checks the exact authority granted. Conversational instructions choose a request; a separate trusted confirmation event must mint the approval receipt.

## Threat model

AgentPorter runs under a host user with writeable repositories, model credentials and possibly SSH/GitHub credentials. General-purpose exec, networked sandbox commands, local HTTP calls and writable worker CLIs are **not** equivalent to safe, task-limited capabilities. Any worker running under the same Unix identity as the receipt signer can potentially steal a signing key or forge approvals. An MCP bearer key and ChatGPT's **Always ask** setting do not attest that a named human approved a particular operation. Model output is never an approval receipt.

## Four action classes

| Category | Initial rule | Example |
| --- | --- | --- |
| ALLOW | Preapproved read-only capability in an authorized workspace | file reads, logs, status |
| SCOPE | Require server-verifiable job scope and temporary workspace/operation permission; default read-only | edit patch, execute tests |
| APPROVAL | Require separate human-verifiable receipt bound to exact operation and target | remote fetch/pull, local HTTP POST, cluster submit |
| LOCKED | Never execute until explicit authorization machinery and isolation exist; fail closed | Git commit/push and untrusted publication |

The complete **53-operation mapping** in [agent-roster-action-policy.md](agent-roster-action-policy.md) defines overridable defaults. No unknown new action inherits ALLOW, and strictly excluded host capabilities have no public action ID.

## Owner-configurable exposure and authorization policy

The complete 53-action matrix defines **shipped defaults, not immutable owner
preferences**. Every action that AgentPorter intentionally exposes through MCP
may have its mode independently overridden by an authenticated operator:
ALLOW, SCOPE, APPROVAL, or LOCKED. Overrides can further narrow to workspace,
named worker, path, endpoint, or Git target. Precedence is an exact scoped
override, then an action override, then the shipped default; more specific
deny rules win on conflict. The operator policy resides in an access-controlled
store **outside all agent-writable workspaces**, versioned and audited. Merely
editing repository documentation, a config file accessible to a worker, or
sending an MCP request must never change policy.

Example **proposed configuration contract** (not recognized by the current
server and not a mechanism to grant access today):

```yaml
version: 1
default_on_unknown_action: deny
action_modes:
  read_file: ALLOW
  dispatch_agent: SCOPE
  git_commit: APPROVAL
  git_push: APPROVAL
scoped_modes:
  - action: dispatch_agent
    workspace_id: Qman
    agent: jax
    mode: SCOPE
```

Permission mode is **distinct from a hard technical safety invariant**.
Changing `git_push` from LOCKED to APPROVAL can request a publication flow
only *after* the separately controlled publisher and signed one-use receipt
issuer exist; it cannot authorize direct host Git, expose credentials, or
unlock a missing backend. Neither ALLOW nor any more permissive override
can disable path confinement, sandboxing, receipt requirements imposed by
sensitive execution backends, or transaction integrity. The server must
report `blocked_backend_unavailable` rather than pretend a policy override
succeeded. The current implementation remains fail-closed.

**Excluded actions have no configurable mode and no public registration.**
Host/root/system administration (including sudo, systemctl, service restart,
OS package installation, account management, agent-triggered release
activation), arbitrary SSH/host shell, credential export, force-push,
destructive ref rewriting, and forged approvals must be absent from all
MCP discovery and REST/OpenAPI catalogs. An owner who needs host maintenance
runs a **separate human-owned administrative workflow**, not an MCP policy
override. Maintain a negative registry/contract test so the server fails
build or startup on accidentally exposed host administration endpoints.
Indirect access through exec, loopback, and worker CLIs requires OS-level
containment; hiding tool names is insufficient.

A complete implementation must atomically validate operator identity,
override revision, action and scope, independent approval proof (if required),
and backend technical capability, and log the effective decision. Unknown
action IDs and invalid modes fail closed. No deployed action becomes
unrestricted simply because the policy store is missing or unreadable.

## Required approval receipt

The receipt must be minted by a **separate trusted approval process** (distinct Unix uid or external authenticated device/service), not by any AgentPorter worker, not from a caller-supplied boolean, and not from the model's verbal assertion.

Required immutable claims:

- Unique one-use nonce; issuer identity and cryptographic signature.
- Exact `action` and `workspace_id`; canonical path or object ID(s), no arbitrary wildcard.
- Named worker ID when delegated; effective model and provider evidence recorded separately.
- Scope: approved files, command argv digest, network endpoints, remote/branch/ref, or staged Git tree hash as appropriate.
- UTC issued-at/expiry (minutes, not a reusable session entitlement), maximum invocations = 1.
- Optional dry-run/result evidence digest; approval must be invalidated when reviewed content changes.
- Requesting client/session identifier, operator acknowledgment event, and unique audit ID.

The server verifies signature, audience, freshness, immutable target, permitted workspace, issuer trust, nonce not previously consumed, and binds consumption atomically to the invocation. Fail closed on every mismatch; record both denials and successes without logging credentials.

## Mandatory server-side enforcement points

1. A shared authorization evaluator covers **MCP and REST**, including the direct tools; never rely solely on MCP descriptive annotations, OpenAPI consequences, or client prompts.
2. Direct execution is not trusted as an opaque argv when a stronger action is locked. Run commands only in a sandbox that **cannot access protected Git metadata, host secrets, publication credentials or unrestricted network** unless the exact capability and receipt authorize them. Prefix-based shell filters are not an isolation boundary.
3. Host-user CLI workers must be put behind comparable OS-level containment or a separately controlled execution principal before broad SCOPE/APPROVAL can be enforced; keep unsupported workers fail-closed for read-only tasks.
4. Git commits and pushes must happen through a dedicated minimal publisher that checks the approved staged-tree digest, branch, remote and expected upstream SHA; no general worker holds publisher credentials. Force push and remote replacement remain prohibited.
5. Network execution should default offline for **both** MCP and REST; a network capability must explicitly name destination, purpose and whether any credentials are needed. Move SSH/GH credential mounts out of generic command execution.
6. Existing SciNet approvals have their own audited reviewer and field checks. Preserve that mechanism, do not allow an agent to self-approve, and only consolidate it with the new receipt service after independent review.
7. Use two-phase requests: `request_authorization` produces a non-secret reviewable summary; a trusted device/service supplies the signed receipt. `perform_authorized_action` consumes the receipt once; the agent cannot mint it.

## Example permitted interaction

1. User says: “Have Liz inspect Qman.” ChatGPT may invoke `list_agents`, `git_diff` and `dispatch_agent(read_only=true)`; no publish rights.
2. User says: “Let Liz edit just the tests.” AgentPorter creates a scoped write job for that workspace/path set; a CLI that cannot enforce the scope must refuse.
3. User says: “Commit this tested diff and push main.” ChatGPT requests publication. The approval service presents the branch, remote, target commit/tree digest and diff summary for authenticated confirmation.
4. User confirms through the trusted channel; a one-shot signed receipt is issued. The dedicated publisher consumes it, checks the diff is unchanged, commits and pushes only that target, and emits an auditable result. If anything changed, reapproval is required.

**Voice can express the request**, but cannot bypass the separate confirmation channel. If ChatGPT receives no trusted receipt, it reports “approval required” and performs no publication.

## Security acceptance tests before enabling

- Forged/expired/replayed/modified receipts fail.
- A read-only worker cannot edit files, Git metadata, or secrets.
- SCOPE cannot change unrelated workspace files, refs or network destinations.
- Generic shell and worker runtimes cannot bypass publication locks by invoking another Git binary, Python process, hook, GitHub CLI or local HTTP listener.
- No worker can read or use approval-signing or publisher credentials.
- Controlled end-to-end receipt flow, including cancellation and TOCTOU changes.
- MCP/REST same denial for missing permissions; no client-app-only bypass.
- Independent audit finds no high or critical path from an unapproved model/tool call to publish or host credential disclosure.

## Rollout

**Phase 1 (this candidate):** seven-name public allowlist, live inventory, 53-action classification and regression coverage; dedicated Git commit/push endpoints locked; fix Git fetch read-only, pull fast-forward-only, bounded synchronous and asynchronous output and MCP ingress cap. No claim of full permission enforcement.

**Phase 2:** protected operator-owned action-mode override store for all 53 exposed actions, trusted approval issuer and one-time signed receipt verification, explicit server audit ledger, centralized action evaluator. Keep publication technically locked until the publisher and approval backend exist, regardless of configured mode.

**Phase 3:** OS-confined workers and generic execution with host credentials isolated. Only then enable receipt-gated commit/push; demonstrate negative tests under every runtime, including Wei and Argie.

**Phase 4:** integrate a user-approved ChatGPT/voice-to-trusted-confirmation experience. Device prompts or a local companion approval workflow are required until the platform provides verifiable user attestation.


Proposed scoped R-metadata HTTPS exception (not deployed): see the reviewed proposal at docs/scoped-cranary-public-https.md; missing private operator approval means fail closed. Generic shell networking remains disabled.
