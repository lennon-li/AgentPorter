# AgentPorter named-agent roster and action authorization matrix

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

These are **desired policy decisions**, not existing end-to-end enforcement.
In this candidate only the dedicated direct `git_commit` and `git_push`
tools are locked (MCP and REST). **This is not a global Git publication
block:** general-purpose `exec_run`/`exec_start` tools, writable agents,
network-enabled execution and external services can still change repository
metadata or publish indirectly. The future authorizer must cover those paths
with OS-enforced restrictions or isolated execution identities. The current
ChatGPT `Always ask` connector setting is a separate, client-side layer.
This candidate must not be represented as voice-approval-ready.

## Exhaustive live action inventory (53 MCP tools)

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
| `exec_run` | **SCOPE** | Bubblewrap sandbox; MCP defaults offline, REST currently defaults online. Arbitrary commands may write/publish; future scope gate required. |
| `exec_start` | **SCOPE** | Same as exec_run; keep job ID and bounded lifetime. |
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
| `git_commit` | **LOCKED** | Dedicated API endpoint denied by default; indirect execution bypass remains until full sandbox scope enforcement. |
| `git_push` | **LOCKED** | Dedicated API endpoint denied by default; networked shell/worker bypass remains until full gate. |
| `scinet_record_approvals` | **APPROVAL** | Existing per-stage, per-experiment fixed-reviewer confirmation mechanism; never treat speech or worker text as human approval. |

## Permanently prohibited capabilities

Unrestricted host shell, arbitrary SSH to private systems, sudo/root/system changes,
credential or token disclosure, workspace traversal, installing hidden MCP servers,
inherited privileged plugin execution, `git push --force`, destructive branch
rewrites, bypassing a model/account policy, and manufacturing human approvals
must **never** be exposed as general agent actions. These are not standalone public capabilities in the
53-action MCP list. **Not all equivalent shell/worker actions are currently
OS-blocked**; unrestricted networked execution and host-user CLI delegation
remain residual risks. This is a policy goal, not a claim of enforcement.

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

### Catalog integrity

Derived from the actual 53 registered AgentPorter tools available to the
connected a7 client on 2026-10-19. The condensed `get_capabilities` list
advertises fewer tools and is **not** a reliable exhaustive action catalog.
Maintain this document from a live schema export, and make the 53-name
inventory a regression fixture so tool additions cannot silently become
authorized by default.
