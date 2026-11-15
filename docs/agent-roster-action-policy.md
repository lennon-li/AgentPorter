# Agent profiles and action authorization

AgentPorter provides seven generic public profiles. Configure their credentials,
models, resource limits, and isolated runtimes locally. Discovery reports
availability and delegation readiness separately; registration alone does not
prove that a provider call will succeed. An unavailable profile never borrows
another profile's credentials or silently changes providers.

| Profile | Runtime | Purpose |
| --- | --- | --- |
| `codex_review` | Codex | Review, debugging and verification |
| `codex_impl` | Codex | Implementation, refactoring and tests |
| `codex_research` | Codex | Research and analysis |
| `copilot_agent` | GitHub Copilot CLI | Coding and review |
| `opencode_free` | OpenCode | Coding through the reviewed free-model route |
| `claude_agent` | Claude Code | Coding and review |
| `agy_agent` | Antigravity | Coding and review |

Generic CLI adapters are runtime infrastructure. Public delegation uses the
named profiles and requires a verified confinement runtime, an admitted
workspace, and the appropriate client grant. Writable delegation explicitly
requires `read_only=false` and `dispatch_write`; the default remains read-only.
Provider/model provenance is reported without claiming unverified live usage.

## Operator-overridable matrix

All 35 public actions have operator-overridable default modes. The protected
`action-policy.yaml` file may contain action defaults and exact workspace/agent
`scoped_modes`. Unknown actions and malformed policies fail closed. Policy can
narrow permissions; it cannot bypass kernel confinement, workspace scopes,
immutable credential handling, resource budgets, or backend authorization.

- **ALLOW:** Read-only operation within an already authorized scope.
- **SCOPE:** Requires the operation's workspace, path, job and mode checks.
- **APPROVAL:** Requires the backend's independent operation-specific approval.
- **LOCKED:** Denied; a caller boolean or conversational request cannot unlock it.

Ordinary scoped fetch, pull, clone and local commit do not require phone
signing. Clone is a typed `git_pull` operation. Every agent push remains denied;
the owner publishes independently. A denied commit policy also prevents writable
delegation because the native Git capability cannot selectively withhold commits.
Client-side tool confirmation is a separate layer from server authorization.

| Action | Default mode | Boundary / reason |
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
| `write_file` | **SCOPE** | Explicit writable workspace, allowed path, reversible diff. |
| `apply_patch` | **SCOPE** | Explicit writable workspace, patch review. |
| `mkdir` | **SCOPE** | Explicit writable workspace/path. |
| `move_path` | **SCOPE** | Explicit writable workspace; conflict guard. |
| `trash_path` | **SCOPE** | Recoverable trash only; no permanent delete. |
| `exec_run` | **SCOPE** | Bounded offline Bubblewrap commands in an authorized workspace; approved public-data GET/HEAD metadata uses a fixed broker without generic shell internet access. |
| `exec_start` | **SCOPE** | Offline by default; owner-approved metadata workers have bounded lifetimes, output and cancellation. |
| `https_download` | **SCOPE** | Separate owner-approved binary acquisition to a fixed research directory; bounded GET, SHA256 receipt, no redirects or overwrite. |
| `job_cancel` | **SCOPE** | Only authorized job; report actual cancellation state. |
| `git_add` | **SCOPE** | Stage only exact approved paths; no commit. |
| `git_checkout` | **SCOPE** | Only approved branch/worktree, inspect dirty changes before switch. |
| `dispatch_agent` | **SCOPE** | Only one of seven named IDs; default read-only; scoped write opt-in. |
| `local_http_request` | **APPROVAL** | Explicit port + method + body review; loopback can mutate services. |
| `git_fetch` | **SCOPE** | Exact protected remote/workspace authority; tracking-only acquisition, no phone signing. |
| `git_pull` | **SCOPE** | Exact scoped pull/clone; private integration, conflict checks and verified publication, no phone signing. |
| `git_commit` | **SCOPE** | Writable workspace commits require no phone receipt; delegated commits use private Git state and a verified offline import. |
| `git_push` | **LOCKED** | Agent publication is denied through REST/MCP and provider-scoped worker networking. |

## Permanently excluded capabilities

Unrestricted host shell/SSH, `sudo`, `systemctl`, service restarts, account or OS
administration, credential export, uncontrolled deployment, force-push, and
approval forgery are not MCP/REST actions. They must remain absent from discovery
and OpenAPI. Generic execution and delegated workers must also be confined
against indirect access. System administration belongs to the independent owner.

The live `get_capabilities` response is authoritative for the installed action
inventory and effective policy. Documentation edits do not grant permissions.
See the [security model](security-model.md), [authorization design](action-authorization-design.md),
and [delegation guide](delegation-guide.md).
