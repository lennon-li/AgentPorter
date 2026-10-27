# AgentPorter

> A local-first Model Context Protocol (MCP) gateway for controlled development
> workspaces, sandboxed code execution, Git inspection, artifacts, and AI coding
> agent delegation.

AgentPorter lets MCP-capable clients work with local development environments
without giving the client unrestricted host access.

## Current capabilities

- **Workspace-scoped access** using registered workspace IDs instead of arbitrary host roots.
- **Sensitive-path controls** shared by file reads, writes, patches, and search.
- **Sandboxed direct execution** for Bash, Python, R, and other installed runtimes through Bubblewrap.
- **No-network direct execution** with scrubbed environment and private `/tmp`.
- **Bounded async jobs** with SQLite state, cancellation, timeout, and output limits.
- **Read-only Git inspection** with bounded output and defensive Git configuration.
- **Artifact retrieval** with response-size limits.
- **Explicit loopback HTTP allowlists** per workspace.
- **Named worker discovery and delegation interface** for installed coding-agent CLIs; the candidate blocks launches pending verified OS confinement.
- **Truthful provenance fields** that separate configured routing, requested overrides, and verified actual model.

## Desired action authorization matrix

**Target policy, not the current production permission state.** The owner
can override the initial mode of **every intentionally exposed action**. An
override may enable a less restrictive workflow only when the necessary
technical enforcement exists; it can never disable workspace containment,
network/credential isolation, or required independently verifiable approval.
No new action is implicitly allowed. Changes must come from an authenticated,
audited operator control plane outside agent-writable repositories—not from an
agent, a chat prompt, or a writable project file.

| Target mode | Meaning | Normal owner interaction |
| --- | --- | --- |
| **ALLOW** | Read-only or bounded inspection in an already authorized workspace | No additional AgentPorter confirmation |
| **SCOPE** | Mutations or execution restricted to the approved workspace, files, agent, task and duration | Specify task/scope; explicit write authorization |
| **APPROVAL** | Remote, publication, transfer or high-impact actions with an exact one-time signed owner approval | Review operation details and confirm through a trusted channel |
| **LOCKED** | Owner-selectable temporary disable for *any exposed action* | Reject until the owner changes policy and backend prerequisites are met |

The desired initial modes for all **53 exposed MCP actions** are below.
These are *recommended defaults*, not permanent privilege ceilings.

| MCP action | Desired default | Scope or approval boundary |
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
| `exec_run` | **SCOPE** | Bubblewrap sandbox; MCP and REST default offline; attempts to enable generic networking are rejected. Arbitrary commands may write workspace content; future scope gate required. |
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
| `git_commit` | **APPROVAL** | Publication by a separate verified publisher, bound to a reviewed tree/remote/ref; currently technically disabled. |
| `git_push` | **APPROVAL** | Publication by a separate verified publisher, bound to a reviewed tree/remote/ref; currently technically disabled. |
| `scinet_record_approvals` | **APPROVAL** | Existing per-stage, per-experiment fixed-reviewer confirmation mechanism; never treat speech or worker text as human approval. |

**Important current limitations:** The review candidate defaults
`git_commit` and `git_push` to **LOCKED**, and now explicitly rejects
`git_fetch` and `git_pull` until a scoped network-capable Git transport
and trustworthy approval path exist. Worker delegation is also blocked until
OS-confined launch is available. The initial `action-policy.yaml` loader can
enforce restrictive owner changes, but **does not yet implement** a complete
authenticated override UI, per-task scoped receipts, or safe permission
escalation. The earlier production release is separate from this PR.

### Capabilities intentionally *not* exposed

Unrestricted host shell/SSH, `sudo`, `systemctl`, service restarts,
OS/package and account administration, credential export, unreviewed
AgentPorter deployment, destructive Git history rewriting/`push --force`,
and approval forgery are **not MCP/REST actions** and cannot be enabled
through a policy override. Blocking only a tool name is insufficient:
generic execution and delegated workers must also be kernel-confined
against indirect access.

### Two independent authorization layers

1. **ChatGPT → a7 connector:** The ChatGPT tool permission setting controls
   when the client asks before sending a tool call. It does not issue
   trusted AgentPorter approval receipts.
2. **AgentPorter → local tool/worker:** Workspace permissions, the operator
   action matrix, isolated execution, scoped grants and one-use approvals
   determine whether the requested operation may actually execute.
   An instruction by voice may request an override; it cannot itself mint
   a verified approval.

Seven named public worker identities are **Jax, Liz, Prof, Phil, Wei, Ming,
and Argie**; generic adapter runtimes are not additional user-selectable
agents, and Tracker is excluded. Runtime availability is checked separately
from registration or policy eligibility.

See the [complete roster and current-mode inventory](docs/agent-roster-action-policy.md)
and [authorization implementation design](docs/action-authorization-design.md).

## Trust boundaries

Direct code execution is kernel-isolated with Bubblewrap.

Worker-agent delegation is different: installed CLIs historically ran as the
host user with access to provider credentials and network. The security-review
candidate **fails closed** on delegated launches until an independent OS
confinement backend exists. Discovery of an agent does not mean it can execute.
A read-only workspace must never be made writable by an agent request.

See [SECURITY.md](SECURITY.md).

## Status

**Early alpha / active dogfooding.**

"Dogfooding" means using your own product for real work while it is still under
development. The purpose is to discover failures, awkward interfaces, missing
controls, and real security requirements before designing features speculatively
or releasing broadly.

Current platform target: Linux and WSL2 with Python 3.11+ and Bubblewrap.

## Install

```bash
git clone https://github.com/lennon-li/AgentPorter.git
cd AgentPorter
pip install -e ".[dev]"
```

AgentPorter is not published to PyPI yet.

## Configure

Create `~/.config/agentporter/workspaces.yaml`:

```yaml
workspaces:
  my-project:
    path: /home/user/projects/my-project
    writable: true
    allow_execute: true
    allow_git: true
    allow_artifacts: true
    allow_agent_dispatch: false
    local_http_ports: []
```

The default server configuration binds only to localhost and uses the
`X-AgentPorter-Key` API-key header. On first startup, AgentPorter generates a
key in `~/.config/agentporter/secrets.env` with restrictive permissions.

## Run

```bash
agentporter doctor
agentporter serve --host 127.0.0.1 --port 8765
```

## Documentation

- [Architecture](docs/architecture.md)
- [Security model](docs/security-model.md)
- [Package vs. local separation](docs/package-vs-local.md)
- [Local setup](docs/local-setup.md)
- [Deployment and verified activation](docs/deployment.md)
- [MCP clients](docs/mcp-clients.md)
- [ChatGPT access through an OpenAI Secure MCP Tunnel](docs/openai-tunnel-setup.md)
- [Knowhere AgentPorter and ChatGPT setup runbook](setup.md)
- [Worker delegation guide](docs/delegation-guide.md)
- [Named-agent roster and action authorization matrix](docs/agent-roster-action-policy.md)
- [Owner approval, overrides and sandbox design](docs/action-authorization-design.md)
- [AgentPorter branch/worktree cleanup and recovery manifest](docs/repository-cleanup-20261019.md)
- [Microsoft Copilot Studio](docs/copilot-studio.md)
- [Roadmap / TODO](TODO.md)

## Development

```bash
pytest -v tests/
```

The repository intentionally does not choose a public software license yet.
