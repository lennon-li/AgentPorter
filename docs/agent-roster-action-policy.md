# Named workers and action policy

Registration, runtime confinement, workspace eligibility and provider readiness
are separate checks. A configured worker is not a guarantee that its provider can
run a job. Never substitute another account, runtime or model after failure.

## Operator-overridable matrix

All 55 public actions have explicit default modes. A protected operator policy
may restrict their exposure, but a mode cannot disable kernel isolation, signed
task requirements or technical locks. A general authenticated confirmation UI and
Git publisher are not yet implemented.

The table lists the legacy defaults. The shared-policy profile treats Git fetch
as SCOPE through its fixed-purpose public-HTTPS transport. It defaults execution
and delegation to read-only, requires signed authority for writable tasks and
requires separate destructive authority for deletion. Specialized grants remain
explicit. See [shared policy](shared-workspace-policy.md).

| Action | Default | Boundary |
| --- | --- | --- |
| `apply_patch` | **SCOPE** | Registered workspace and effective operator policy apply. |
| `dispatch_agent` | **SCOPE** | Configured identity only; read-only default; signed authority for shared-profile edits. |
| `exec_run` | **SCOPE** | Sandboxed and offline by default; shared-profile writes require signed task authority. |
| `exec_start` | **SCOPE** | Sandboxed and offline by default; shared-profile writes require signed task authority. |
| `get_capabilities` | **ALLOW** | Registered workspace and effective operator policy apply. |
| `git_add` | **SCOPE** | Registered workspace and effective operator policy apply. |
| `git_branch` | **ALLOW** | Registered workspace and effective operator policy apply. |
| `git_checkout` | **SCOPE** | Registered workspace and effective operator policy apply. |
| `git_commit` | **LOCKED** | Locked until a separately verified publisher exists. |
| `git_diff` | **ALLOW** | Registered workspace and effective operator policy apply. |
| `git_fetch` | **APPROVAL** | Shared profile uses bounded public-HTTPS fetch; no credentials or publication. |
| `git_log` | **ALLOW** | Registered workspace and effective operator policy apply. |
| `git_pull` | **APPROVAL** | Registered workspace and effective operator policy apply. |
| `git_push` | **LOCKED** | Locked until a separately verified publisher exists. |
| `git_show` | **ALLOW** | Registered workspace and effective operator policy apply. |
| `git_status` | **ALLOW** | Registered workspace and effective operator policy apply. |
| `https_download` | **SCOPE** | Registered workspace and effective operator policy apply. |
| `job_cancel` | **SCOPE** | Registered workspace and effective operator policy apply. |
| `job_output` | **ALLOW** | Registered workspace and effective operator policy apply. |
| `job_result` | **ALLOW** | Registered workspace and effective operator policy apply. |
| `job_status` | **ALLOW** | Registered workspace and effective operator policy apply. |
| `list_agents` | **ALLOW** | Registered workspace and effective operator policy apply. |
| `list_artifacts` | **ALLOW** | Registered workspace and effective operator policy apply. |
| `list_files` | **ALLOW** | Registered workspace and effective operator policy apply. |
| `list_workspaces` | **ALLOW** | Registered workspace and effective operator policy apply. |
| `local_http_request` | **APPROVAL** | Registered workspace and effective operator policy apply. |
| `mkdir` | **SCOPE** | Registered workspace and effective operator policy apply. |
| `move_path` | **SCOPE** | Registered workspace and effective operator policy apply. |
| `qman_consult` | **LOCKED** | Locked pending an immutable or confined external advisory backend. |
| `read_artifact` | **ALLOW** | Registered workspace and effective operator policy apply. |
| `read_file` | **ALLOW** | Registered workspace and effective operator policy apply. |
| `scinet_diagnostic` | **ALLOW** | Registered workspace and effective operator policy apply. |
| `scinet_environment_check` | **ALLOW** | Registered workspace and effective operator policy apply. |
| `scinet_inference_approve` | **APPROVAL** | Registered workspace and effective operator policy apply. |
| `scinet_inference_preflight` | **ALLOW** | Registered workspace and effective operator policy apply. |
| `scinet_inference_provision` | **APPROVAL** | Registered workspace and effective operator policy apply. |
| `scinet_inference_results` | **ALLOW** | Registered workspace and effective operator policy apply. |
| `scinet_inference_stage` | **APPROVAL** | Registered workspace and effective operator policy apply. |
| `scinet_inference_submit` | **APPROVAL** | Registered workspace and effective operator policy apply. |
| `scinet_job_logs` | **ALLOW** | Registered workspace and effective operator policy apply. |
| `scinet_job_status` | **ALLOW** | Registered workspace and effective operator policy apply. |
| `scinet_login` | **APPROVAL** | Registered workspace and effective operator policy apply. |
| `scinet_preflight` | **ALLOW** | Registered workspace and effective operator policy apply. |
| `scinet_record_approvals` | **APPROVAL** | Registered workspace and effective operator policy apply. |
| `scinet_setup` | **APPROVAL** | Registered workspace and effective operator policy apply. |
| `scinet_setup_status` | **ALLOW** | Registered workspace and effective operator policy apply. |
| `scinet_stage` | **APPROVAL** | Registered workspace and effective operator policy apply. |
| `scinet_submit` | **APPROVAL** | Registered workspace and effective operator policy apply. |
| `search_text` | **ALLOW** | Registered workspace and effective operator policy apply. |
| `server_deploy_info` | **ALLOW** | Registered workspace and effective operator policy apply. |
| `trash_path` | **SCOPE** | Shared-profile deletion requires separately signed destructive authority. |
| `venkata_diagnostic` | **ALLOW** | Registered workspace and effective operator policy apply. |
| `venkata_transfer` | **APPROVAL** | Registered workspace and effective operator policy apply. |
| `workspace_info` | **ALLOW** | Registered workspace and effective operator policy apply. |
| `write_file` | **SCOPE** | Registered workspace and effective operator policy apply. |

## Permanently excluded capabilities

Host administration, arbitrary SSH, credential export, force-push, destructive
history rewriting and approval forgery are not MCP/REST actions. They cannot be
enabled by changing an action mode. Operator maintenance is a separate workflow.

## Identity and provenance

The named roster is configured separately from generic CLI adapters. Inspect
runtime eligibility and workspace admission before dispatch. CLI output does not
by itself prove which model ran. Missing trusted provenance is reported as
unknown. Account usage and live job records belong in private operator storage.
