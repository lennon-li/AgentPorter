# A7Dev action map for ChatGPT

Recorded: 2026-10-22. Scope: the public A7Dev MCP/REST interface on Asgard.

A7Dev lets an authenticated assistant inspect registered projects, edit permitted
files, run bounded code, and delegate to configured agents. It does not grant
unrestricted control of Asgard. Permissions are separate for each workspace and
operation: read access does not imply write, execution, delegation, or networking.

This is an explanatory snapshot, not a permission grant. It records the reviewed
implementation and installation evidence. The complete effective workspace
permissions have **not been freshly verified through authenticated A7Dev** in
this conversation. Example policy files and historical plans are not proof of
current grants. A listed tool may still reject an operation.

## Actions and boundaries

| Action | Tools | Boundary / current behavior |
| --- | --- | --- |
| Inspect the gateway | `get_capabilities`, `server_deploy_info` | Authenticated introspection; grants no additional access. |
| Discover projects and agents | `list_workspaces`, `workspace_info`, `list_agents` | Registered and client-authorized scope. Agent registration does not establish provider authentication, quota, or successful execution. |
| Browse project files | `list_files`, `search_text`, `read_file` | Authorized workspace; protected paths and output/file limits apply. |
| Read artifacts | `list_artifacts`, `read_artifact` | Authorized workspace and bounded results. |
| Inspect Git | `git_status`, `git_diff`, `git_log`, `git_show`, `git_branch` | Git-read grant; branch listing does not change branches. |
| Edit project files | `write_file`, `apply_patch` | Writable workspace, client write grant, and an authorized task. |
| Organize project files | `mkdir`, `move_path`, `trash_path` | Write grant and authorized paths. Trash is recoverable; no permanent-delete tool. |
| Run code and tests | `exec_run`, `exec_start` | Execution grant; sandboxed, bounded runtime/output/resources; normally offline. Workspace write policy applies. |
| Inspect jobs | `job_status`, `job_output`, `job_result` | Public clients are restricted to recorded jobs within their workspace scope. |
| Cancel jobs | `job_cancel` | Backend and client policy must admit cancellation; not universally available. Current public policy has no cancellation grant mapping. |
| Delegate tasks | `dispatch_agent` | Separate dispatch grant, admitted workspace, named agent, supported confinement, and available provider/account. Defaults to read-only. |
| Permit worker edits | `dispatch_agent(read_only=false)` | Requires writable workspace plus `dispatch`, `write`, and `dispatch_write` client grants and runtime support. Ordinary dispatch permission is insufficient. |
| Download files | `https_download` | Separate owner-installed HTTPS scope: approved hosts/paths, fixed destination, byte/time limits, hash receipts, no overwrite. Redirects currently rejected. |
| Retrieve web metadata | `exec_run` / `exec_start` with the approved HTTPS broker request | Only fixed, policy-approved GET/HEAD requests. This does not enable shell internet access. |
| Stage Git files | `git_add` | Separate client `git_write` grant, writable workspace, exact authorized paths. |
| Switch or create branches | `git_checkout` | Separate client `git_write` grant, writable workspace, authorized branch operation. Inspect existing changes first. |
| Commit changes | `git_commit` | Dedicated tool currently locked; independent verified approval/publication support is unavailable. |
| Push changes | `git_push` | Dedicated tool currently locked; chat permission or caller booleans cannot unlock it. |
| Fetch or pull | `git_fetch`, `git_pull` | Dedicated tools currently locked pending a scoped network-capable Git backend and independent approval. |
| Call a local HTTP service | `local_http_request` | Approval-class action; current public-client policy rejects it. Loopback requests can mutate services. |
| Diagnose Venkata | `venkata_diagnostic` | Fixed diagnostic backend exists; current public-client policy rejects this action. No arbitrary SSH. |
| Transfer to Venkata | `venkata_transfer` | Approval-class fixed-target transfer; current public-client policy rejects it. |
| Inspect SciNet | `scinet_diagnostic`, `scinet_job_status`, `scinet_job_logs`, `scinet_setup_status`, `scinet_inference_preflight`, `scinet_inference_results`, `scinet_preflight`, `scinet_environment_check` | Specialized bounded backends exist; current public-client policy rejects these actions. Read/preflight does not authorize submission. |
| Operate SciNet | `scinet_login`, `scinet_stage`, `scinet_submit`, `scinet_setup`, `scinet_inference_stage`, `scinet_inference_provision`, `scinet_inference_approve`, `scinet_inference_submit`, `scinet_record_approvals` | Specialized approval-class operations; current public-client policy rejects these actions. Human Duo and independent approval requirements cannot be supplied by the model. |

The table covers all 54 recognized public action names in the reviewed action
policy. Recognition is distinct from permission and backend readiness.

## What requires human involvement

| Situation | What the human must do |
| --- | --- |
| Ordinary project work within existing grants | Give a bounded task, such as fixing a bug in a named project and running tests. Individual edits need not each receive another confirmation. |
| Add a project or expand read/write/exec/delegation access | Install a reviewed owner-controlled policy change outside agent-writable workspaces. The assistant cannot authorize itself. |
| Enable writable delegation | Explicitly authorize worker edits and install the required additional grants; confirm runtime confinement supports them. |
| Add download hosts, paths, or destinations | Install a reviewed HTTPS policy change; retain transport, resource, and receipt controls. |
| Publish Git changes or perform sensitive remote actions | Use the required operation-specific trusted approval/backend. Saying “yes” cannot replace missing technical support. Currently locked Git tools remain locked. |
| Install releases, restart services, or administer the host | Use a separate human-owned administration workflow outside the public A7Dev interface. |

ChatGPT connector confirmation prompts are an additional client-side layer.
Clicking “Allow” does not override a server denial or produce an independent
server-verifiable approval receipt. The general approval issuer is unfinished;
the `APPROVAL` label must not be read as a working universal approval workflow.

## Excluded from the public interface

- Unrestricted host shell or arbitrary SSH.
- `sudo`, root access, OS/system package administration, or account/permission administration.
- `systemctl`, service restarts, and uncontrolled deployment.
- Reading/exporting authentication credentials or tokens.
- Escaping authorized workspaces or changing protected gateway policy/state.
- Arbitrary shell internet access or private-network probing.
- Force-push and destructive Git history rewrites.
- Manufacturing human approvals or bypassing agent/account/model restrictions.
- Installing hidden MCP servers or inheriting privileged plugin execution.

These must not become public actions merely because a chat request asks for them.
Separate human administration does not grant the assistant corresponding tools.
This list describes intended exclusions; it is not a claim that every possible
indirect bypass has received an independent security audit.

## Latest verified download-specific state

- CRAN query-free paths on exact host `cran.r-project.org` are enabled.
- Approved Posit paths on `packagemanager.posit.co` remain scoped.
- Downloads use the designated Cranary directory, a 16 MiB cap, a 60-second
  timeout, HTTPS/public-IP checks, receipts, and no overwrite.
- Development release `20261022T224004.423620Z` installed the sanitized Posit
  redirect diagnostic. Redirect following remains disabled; destination
  verification and the actual redirect allowance remain pending.
- This installation did not change production.

## Sources and verification limits

- [Public-client enforcement](../src/agentporter/client_policy.py): operation/workspace grants and public-job ownership.
- [Action policy](../src/agentporter/action_policy.py): 54 recognized actions and fail-closed locks.
- [Git tools](../src/agentporter/tools/git.py): current fetch/pull/commit/push denials.
- [Execution tools](../src/agentporter/tools/execution.py): offline execution and separate HTTPS broker.
- [Server registration](../src/agentporter/server.py): tool entry points.
- [Posit installation record](posit-redirect-repair-20261022.md).
- [CRAN acceptance record](a7dev-cranary-install-acceptance-20261022.md).

Verification: source inspection and recorded installation evidence. No permissions,
configuration, services, or runtime behavior were changed to create this file.
To establish a fresh live inventory, use authenticated A7Dev discovery plus
workspace-specific permissions and agent readiness; compare loaded/disk release
identity and inspect protected effective policy through the owner workflow where
the public interface does not expose it. Capability listings alone are not proof
that every action can successfully execute.
