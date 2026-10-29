# AgentPorter named-agent roster and action authorization matrix

> Historical governance baseline (2026-10-19). For the current development
> implementation and installation limits, start with [the action map](A7DEV_ACTION_MAP.md)
> and [consolidated status](A7DEV_CURRENT_STATE.md). Statements below about missing
> confinement and policy overrides describe the earlier candidate. The current
> source implements confined development workers and owner-installed restrictions;
> a general trusted approval issuer and Git publication backend remain unavailable.

**Release blocker:** No confined worker backend or trusted approval issuer
has been implemented. Running a locally installed CLI is not authorization.
Generic asynchronous host launches are rejected unless they match a
trusted offline Bubblewrap command shape. Remote Git/cluster actions remain
subject to separate controls, not an automatic voice allowance.

**Candidate hardening note:** The isolated candidate now refuses delegated host-worker dispatch until a confined worker backend exists, and refuses generic network-enabled execution from MCP and REST. These controls are **not deployed**, and the seven agents remain registered but cannot be called safely through this candidate. The new Git metadata overmount only protects repository-root .git paths; it is not universal Git isolation, scoped authorization, or a publisher approval.

**Date:** 2026-10-19. **Scope:** Asgard MCP / AgentPorter. **Status:** candidate governance policy, not deployed; direct Git commit and push are locked in this candidate.

The seven **named agents** are the approved public delegation choices. The generic CLI
runtimes (Codex, Claude Code, OpenCode, Antigravity) remain **internal infrastructure**,
not extra named agents. No Tracker is approved. Agent discovery is not proof of
a successful model call; preserve model/provider provenance and do not substitute
another model when an agent is unavailable.

## Seven-agent inventory (live pre-change findings)

| Named agent | ID | Runtime | Identity registration | Last live status | Read-only enforcement |
| --- | --- | --- | --- | --- | --- |
| Jax | jax | Codex | Yes | available | Read-only (Codex sandbox) |
| Liz | liz | Codex | Yes | available | Read-only (Codex sandbox) |
| Prof | prof | Codex | Yes | available | Read-only (Codex sandbox) |
| Phil | phil | GitHub Copilot CLI | Yes | available | Writable mode only |
| Wei | wei | Dedicated OpenCode | Yes | unavailable at last live check | Writable mode only; free-model identity |
| Ming | ming | Claude Code | Configured on current Asgard | available | Writable mode only |
| Argie | argie | Antigravity | Configured on current Asgard | available | Writable mode only |

The live AgentPorter registry exposed 11 entries (7 named + 4 runtime aliases).
Last available Wei response reported `available=false` with the built-in
`opencode/glm-5.3-flash-free` route. A local credential repair has **not**
yet been confirmed through a successful live job. Do not borrow generic
`opencode` credentials or silently change Wei's provider/model. Every worker
currently launches as the Asgard host user; AgentPorter does not give delegated
CLIs an independent Linux/container security boundary. Only the Codex family
reports enforced read-only delegation.

## Operator-overridable matrix; non-exposed host capabilities

**All 54 public actions have operator-overridable *default policy modes*.**
The ALLOW / SCOPE / APPROVAL / LOCKED entries below are shipped defaults,
not an immutable list of owner permissions. An authenticated operator may
configure a stricter or more permissive mode for any exposed action, including
the two Git publication actions, when the required enforcement backend exists.
Overrides are per exact action, workspace and, when appropriate, named agent.
They are not permissions that a model, worker, MCP client, chat message, or
repository file can grant itself.

**Policy override is not a bypass of execution prerequisites.** Even after
changing a default, AgentPorter must still enforce workspace confinement,
path/command scoping, credential isolation, trusted short-lived approval receipts
where needed, and the independent Git publisher for remote publication.
Until the trusted authorizer and confined worker/publisher components exist,
an override of a presently LOCKED action remains *ineffective* (fail closed);
no API boolean or editable YAML file may lift these technical gates.
Operator policy changes belong in a protected control plane outside
agent-writable workspaces, with authenticated changes, validation, an audit
trail, atomic versioning, and a safe rollback. The override mechanism is
**specified but not yet implemented**.

**Hard-excluded capabilities are not matrix rows and are not MCP/REST actions.**
Do not register host `sudo`, `systemctl` service management/restarts,
root or OS/package administration, account/permission changes, arbitrary host
SSH/shell, credential export, uncontrolled deployment, force-push or destructive
ref rewriting, or manufacturing approvals as public tools. These operations
must be absent from MCP discovery and OpenAPI, not merely marked LOCKED or
hidden with an annotation. Any separate human-owned system administration
workflow stays outside AgentPorter's exposed agent interface. Generic
execution and delegated CLIs must not offer an indirect path to them; enforce
that with kernel-backed isolation, not command-string filters.

**Effective decision** = a recognized public action + operator-configured
mode + verified caller/scope/receipt + non-overridable backend security gates.
Unknown actions fail closed; modifying this document does not alter runtime
authorization. In particular, the candidate's current delegation gate remains
closed while the confined launcher is missing.

## Permission modes (proposed)

- **ALLOW:** Read-only introspection in a workspace already authorized by the owner;
  never means unrestricted file access or automatic ChatGPT connector consent.
- **SCOPE:** Allow after an explicit bounded task with workspace, affected paths,
  agent, job limits, and mode, with no persistent privilege escalation. Write
  delegations must opt into `read_only=false`.
- **APPROVAL:** Require independent, operation-specific owner approval, with exact
  payload/target and a short-lived verifiable receipt before executing. A voice
  statement alone is **not** an authorization receipt.
- **LOCKED:** Reject through AgentPorter until server-side approval receipt
  verification exists. A UI `Always ask` prompt does not provide an API-level
  proof of owner approval.

These are **initial configurable policy decisions**, not existing end-to-end enforcement.
In this candidate only the dedicated direct `git_commit` and `git_push`
tools are locked (MCP and REST). **This is not a global Git publication
block:** general-purpose `exec_run`/`exec_start` tools and external services can still
write workspace content and could indirectly change Git metadata without further
OS hardening. Generic network-enabled execution and host-user agent dispatch
are deliberately denied in this candidate. The future authorizer must cover those paths
with OS-enforced restrictions or isolated execution identities. The current
ChatGPT `Always ask` connector setting is a separate, client-side layer.
This candidate must not be represented as voice-approval-ready.

## Exhaustive live action inventory (54 MCP tools)

The mode column is the **initial configurable default**, not a permanent restriction. The protected operator control plane (not yet implemented) will own overrides.

| Action | Recommended mode | Boundary / reason |
| --- | --- | --- |
| `get_capabilities` | **ALLOW** | Read server capabilities, not a permission grant. |
| `server_deploy_info` | **ALLOW** | Read live release provenance only. |
| `list_workspaces` | **ALLOW** | Return IDs and status; no new access. |
| `workspace_info` | **ALLOW** | Use registered workspace only. |
| `list_agents` | **ALLOW** | Expose seven named identities; never promise available. |
| `list_files` | **ALLOW** | Registered workspace; existing sensitive-path protections. |
| `search_text` | **ALLOW** | Sensitive-path filters remain mandatory. |
| `read_file` | **ALLOW** | Sensitive-path filters and file-size caps apply. |
| `list_artifacts` | **ALLOW** | Registered workspace and artifact controls. |
| `read_artifact` | **ALLOW** | Registered workspace and response limits. |
| `git_status` | **ALLOW** | No changes to repository. |
| `git_diff` | **ALLOW** | No changes to repository. |
| `git_log` | **ALLOW** | No changes to repository. |
| `git_show` | **ALLOW** | No changes to repository. |
| `git_branch` | **ALLOW** | List only, not checkout. |
| `job_status` | **ALLOW** | Existing job ID; no mutation. |
| `job_output` | **ALLOW** | Existing job ID; bounded output. |
| `job_result` | **ALLOW** | Existing job ID; bounded output. |
| `venkata_diagnostic` | **ALLOW** | Fixed allowlisted diagnostic; no arbitrary SSH. |
| `scinet_diagnostic` | **ALLOW** | Fixed allowlisted diagnostic; no arbitrary SSH. |
| `scinet_job_status` | **ALLOW** | Job ID scoped to approved submission. |
| `scinet_job_logs` | **ALLOW** | Bounded output; approved job only. |
| `scinet_setup_status` | **ALLOW** | Read setup state only. |
| `scinet_inference_preflight` | **ALLOW** | Offline verification; no submission. |
| `scinet_inference_results` | **ALLOW** | Ledger-bound read; fails closed when unsupported. |
| `scinet_preflight` | **ALLOW** | Read-only validation. |
| `scinet_environment_check` | **ALLOW** | Fixed environment check. |
| `write_file` | **SCOPE** | Explicit writable workspace, allowed path, reversible diff. |
| `apply_patch` | **SCOPE** | Explicit writable workspace, patch review. |
| `mkdir` | **SCOPE** | Explicit writable workspace/path. |
| `move_path` | **SCOPE** | Explicit writable workspace; conflict guard. |
| `trash_path` | **SCOPE** | Recoverable trash only; no permanent delete. |
| `exec_run` | **SCOPE** | Bubblewrap commands remain offline; a separately operator-approved cranary GET/HEAD metadata broker is proposed, without generic shell internet access. Arbitrary commands may write workspace content; future scope gate required. |
| `exec_start` | **SCOPE** | Offline-by-default; a proposed owner-approved metadata worker has bounded lifetime and cancellation. |
| `https_download` | **SCOPE** | Separate owner-approved binary acquisition to a fixed research directory; bounded GET, SHA256 receipt, no redirects or overwrite. |
| `job_cancel` | **SCOPE** | Only authorized job; report actual cancellation state. |
| `git_add` | **SCOPE** | Stage only exact approved paths; no commit. |
| `git_checkout` | **SCOPE** | Only approved branch/worktree, inspect dirty changes before switch. |
| `dispatch_agent` | **SCOPE** | Only one of seven named IDs; default read-only; scoped write opt-in. |
| `local_http_request` | **APPROVAL** | Explicit port + method + body review; loopback can mutate services. |
| `venkata_transfer` | **APPROVAL** | Approved file hashes and fixed destination; data exfiltration risk. |
| `scinet_login` | **APPROVAL** | Human performs Duo; caller cannot approve for human. |
| `scinet_stage` | **APPROVAL** | Approved digest, destination, size budget. |
| `scinet_submit` | **APPROVAL** | Approved template, allocation budget, reviewer. |
| `scinet_setup` | **APPROVAL** | Fixed verified setup template, staged artifact. |
| `scinet_inference_stage` | **APPROVAL** | Approved exact bundle digest to fixed scratch. |
| `scinet_inference_provision` | **APPROVAL** | Remote inference environment provisioning; exact manifest/digest and authorized path, never unreviewed installation. |
| `scinet_inference_approve` | **APPROVAL** | Verify offline independent signature; do not self-approve. |
| `scinet_inference_submit` | **APPROVAL** | Signed exact stage + allocation quota. |
| `git_fetch` | **APPROVAL** | Remote-only plus workspace metadata change; no read-only fetch. |
| `git_pull` | **APPROVAL** | Branch and remote explicit, clean-tree and conflict checks. |
| `git_commit` | **SCOPE** | Writable workspace commits require no phone receipt; delegated commits use private Git state and a verified offline import. |
| `git_push` | **LOCKED** | Agent publication is denied through REST/MCP and provider-scoped worker networking. |
| `scinet_record_approvals` | **APPROVAL** | Existing per-stage, per-experiment fixed-reviewer confirmation mechanism; never treat speech or worker text as human approval. |

## Permanently excluded capabilities (not operator-overridable)

Unrestricted host shell, arbitrary SSH to private systems, sudo/root/system
changes, account and package administration, credential or token disclosure,
workspace traversal, installing hidden MCP servers, inherited privileged
plugin execution, `git push --force`, destructive branch rewrites, bypassing
model/account policy, and manufacturing human approvals must **never be public
MCP/REST operations**. They are not among the 54 public action names, and no
operator override may turn an excluded capability into a new public action.

Absence from discovery alone does not guarantee containment: a generic shell,
local loopback service or host-user worker could still provide indirect access
without OS-enforced isolation. The candidate blocks generic outbound networking
and unconfined worker launches, but independent attack testing and complete
authorization are still required before production activation.

The [operator-verified authorization design](action-authorization-design.md)
specifies the additional server-side receipt and OS containment required to
turn this classification into enforceable voice-driven permissions.

## Enforcement checklist

1. Public `list_agents` returns exactly the seven in this document, including
   unavailable or unregistered named entries without pretending they can run.
2. Public `dispatch_agent` refuses generic runtime IDs, Tracker, and other
   unapproved aliases. Internal adapters remain usable by the named routes.
3. A worker that cannot enforce read-only mode must be rejected for a
   `read_only=true` task. Edit authorization never grants Git publish rights.
4. Wei retains its independent built-in free-model credential restrictions.
   Verify `detect` and a completed end-to-end test; never fallback to
   generic OpenCode.
5. Before rollout of the action matrix, implement a centralized server-side
   authorizer for **MCP, REST, and direct/indirect command paths**, fail closed
   when approval receipts are absent, and audit authorization decisions.
6. Run negative security tests for path escapes, worker command syntactic
   bypasses, Git metadata writes, loopback/remote network, MCP inheritance,
   and forged approval/commit/push requests. Independent audit required.
7. Activate with the trusted immutable deployment gate, and compare live
   release fingerprint, actual agent roster, and operation behavior.
8. Build the protected operator-owned override policy store; cover all 54
   actions, default to the shipped modes, reject unknown action IDs, and deny
   attempts to introduce hard-excluded host operations into MCP or REST.
9. Test both policy overrides and runtime invariant gates; a more permissive
   requested mode must not bypass confinement, receipt checking, or publication.

### Catalog integrity

Derived from the actual 54 registered AgentPorter tools available to the
connected a7 client on 2026-10-19. The condensed `get_capabilities` list
advertises fewer tools and is **not** a reliable exhaustive action catalog.
Maintain this document from a live schema export, and make the 54-name
inventory a regression fixture so tool additions cannot silently become
authorized by default.
