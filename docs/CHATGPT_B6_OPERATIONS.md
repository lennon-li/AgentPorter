# ChatGPT operations on BCC / B6

Updated 2026-11-13. This manual describes the activated BCC consolidation.
The generated gateway `/openapi.json` is the authoritative argument schema;
its captured copy is `artifacts/bcc-consolidation-20261112/active-openapi.json`.
There are 31 published `bcc_` operations. Keep the existing connection's API key
in its authentication header, never in prompts, URLs, files, or job packets.

## Discover and select scope

1. Call `bcc_list_workspaces`, then `bcc_workspace_info` with the exact returned
   workspace ID. The obsolete, missing `bcc-production-canary` registration has
   been removed. `qman` and writable `obsidian` are available on BCC.
2. Call `bcc_list_agents` for that workspace. Availability proves an executable
   and OS confinement probe; it does not prove quota or model entitlement.
3. Use the requested identity, provider, model, workspace, and host. A refusal
   does not authorize substituting another account or changing scope.

Wei's task pause and the exclusion of Argie/Agy remediation remain in effect.
Their shared CLI installation/version checks did not dispatch model work.

## Read, edit, and execute

| Operations | Use |
| --- | --- |
| `bcc_list_files`, `bcc_read_file`, `bcc_search_text` | Relative paths in the selected workspace. |
| `bcc_write_file`, `bcc_apply_patch` | Authorized canonical repository edits. Inspect each operation's actual request schema. |
| `bcc_mkdir`, `bcc_move_path`, `bcc_trash_path` | Existing workspace/path authority applies. |
| `bcc_exec_run`, `bcc_exec_start` | An argv array and optional relative cwd; bounded offline execution. |

For example, `bcc_exec_run` with workspace `agentporter` and
`argv:["git","status","--short"]` inspects the repository. Shell command strings
are not argv arrays. Tools available in a terminal are not proof that a confined
worker exposes those tools.

## Delegate and verify an edit

`bcc_dispatch_agent` is `POST /api/v1/workspaces/{workspace_id}/agents/dispatch`.
For a bounded edit, replace the example `request_id` with a fresh 32-character
hexadecimal ID and provide explicit scope:

```json
{
  "request_id": "0123456789abcdef0123456789abcdef",
  "agent": "liz",
  "task": "Make the requested change in this repository, run the relevant checks, and report the diff. Do not commit or push.",
  "purpose": "Owner-authorized repository edit",
  "read_only": false,
  "allow_commit": false,
  "allow_push": false
}
```

Use `read_only:true` for inspection. Ordinary approved edits/tests persist after
successful cleanup. The outer sandbox, private workspace transaction and server
policy enforce scope independently of the task text. Native authentication,
credential sockets, unrelated host files and raw Git history remain inaccessible.

An omitted model preserves the identity's normal selection. For Copilot, omit a
reasoning override when using its automatic/default model; an explicit reasoning
level requires an explicit compatible model. Never infer entitlement from quota.

| Operation | Endpoint |
| --- | --- |
| `bcc_job_status` | `GET /api/v1/jobs/{job_id}/status` |
| `bcc_job_output` | `POST /api/v1/jobs/{job_id}/output` |
| `bcc_job_result` | `POST /api/v1/jobs/{job_id}/result` |
| `bcc_job_cancel` | `POST /api/v1/jobs/{job_id}/cancel` |

Poll the exact returned handle at a modest interval, such as five seconds.
Respect HTTP 429 and `Retry-After`; do not change server limits to speed polling.
Admission/queueing is not execution success. Check terminal status, exit code,
cleanup, then read the changed canonical file or diff. Treat `rejected` as
terminal. Capacity rejection with `launched:false` is not a provider failure.
Never repeat an uncertain execution automatically. Keep the same request ID for
reconciliation; create a new attempt only after proving no execution occurred.

## Live Qman without cached fallback

Call `bcc_qman_consult` with an exact supported provider/profile pair:

```json
{
  "provider": "codex",
  "profile": "jax",
  "model": "gpt-6.1-terra",
  "live": true,
  "allow_cached_fallback": false
}
```

The other admitted capability is `provider:"copilot", profile:"phil"`.
Read `agentporter.mode`, `cached_fallback_used`, the collector result, source,
observation/freshness timestamps, units and windows. A successful HTTP request
alone does not establish fresh quota. The Codex collector uses the same shared
Codex 0.169.0 installation; Copilot uses the matching bundled SDK and shared CLI.
Both the B6 quota service and the terminal `qman` collectors use this shared
selection. The terminal Qman command/store code and database behavior were
preserved; its collector update did not open or change the database.

The existing owner policy authorizes live quota for Jax and Phil only. Liz/Prof
return `live_quota_capability_not_authorized` without starting a provider process
or using cache. Unsupported/ambiguous selectors return
`live_quota_requires_exact_provider_profile`. This repair did not enable the
separate, default-off `qman_refresh` feature or invent a Claude quota collector.

Codex reports session identity checks, while persistent account binding and model
entitlement remain unverified by Qman. Copilot reports native-client quota; retain
its provider-verification and reset-window limitations. In particular, a fresh
collection can contain a historical reset counter: do not convert it into a
current monthly credit balance when the response says `reset_elapsed_historical`.
Dated packaged API prices are reference data, not verified subscription charges.

## Approval and Git publication

Lennon selected **approval in this conversation and owner-run Git**, replacing
the browser signer requirement. B6 `git_commit` and `git_push` remain LOCKED.
Worker booleans, ordinary write authority and approval prose cannot unlock them.
The `bcc_git_commit` operation is published but denied under this policy; no
ChatGPT push operation is published. Raw HEAD/ref/stash changes and commits after
an approved pull cannot bypass the workspace publication boundary.

After an edit, show the owner the exact diff and proposed commit message. The
owner explicitly approves, then runs Git locally. Push requires separate owner
approval and an owner command. An agent-run command is not an owner-run command.
A text or voice instruction can express the same bounded edit intent; this does
not claim an independent voice identity bridge or create a signed B6 Git receipt.
Do not request browser key enrollment for this selected workflow.

`bcc_git_pull`, `bcc_git_add` and `bcc_git_checkout` remain subject to their own
schemas and effective policy; their presence is not blanket Git authority.

## One shared CLI installation

Terminal/system launchers and AgentPorter resolve the same selected executables
under `/opt/agent-clis/current`. Stable `bin/<provider>` links follow vendor layout
changes. Code mounts remain read-only; each native account keeps its own home,
authentication, settings, sessions and history.

| CLI | Selected version on 2026-11-13 |
| --- | --- |
| Codex | 0.169.0 |
| Claude Code | 2.1.323 |
| GitHub Copilot | 1.0.111 |
| OpenCode | 1.19.5 |
| Agy | 1.5.8 |

Use `updateCLI --status` to inspect the selection and `updateCLI` for an
administrator-authorized manual update. `bcc-shared-cli-update.timer` performs
the same shared update daily at 02:00 America/New_York with a small randomized
delay. Its protected service stages vendor code as yeli using an empty HOME;
native credential directories are inaccessible there. Package lifecycle scripts
do not run as root. Only the installed controller imports verified code and
atomically selects it. No permanent sudo grant was added. Per-provider and
per-profile automatic updaters no longer select independent copies. Historical
sealed releases/rollback code are retained; they are not selected installations.

Codex Jax/Liz/Prof use three distinct canonical accounts. The access broker reads
the intended native store; workers receive bounded access with an empty refresh
token. Only the existing native daemon renews Codex authentication. Ming receives
current native Claude access without its refresh token, and Phil receives only
filtered native authentication fields. No worker auth is written back to a
native store. Stale access or a changed enrolled account fails closed and requires
native renewal/re-enrollment, without a copied-token or alternative-account fallback.

## Evidence and limits

| Capability | Evidence | Verification |
| --- | --- | --- |
| Actual external ChatGPT connection | Owner-pasted workspace discovery and live Jax Qman result, 2026-11-13 10:21 EST | Executed externally; reported by owner |
| Current source/PID parity, generated catalog, Git denial, persistent file edit and host isolation | `live-acceptance.json` | Executed locally through authenticated B6 REST |
| Shared CLI paths, versions, daemon inodes and scheduled update | Shared-installation receipt and systemd state | Executed locally |
| Jax, Liz, Prof real responses | Final native smoke receipts | Executed locally through B6 |
| Ming real response | `native-provider-smoke-20261113-v2.json` | Executed locally through B6 |
| Phil real response | `final-phil-zstd-smoke-20261113.json` | Executed locally through B6 |
| Actual delegated canonical edit | `shared-cli-delegated-write-final-20261113.json` | Executed locally through B6 |
| Refresh exclusion, account binding, scope/Git rules and provider policy metadata | Focused security tests and native sandbox tests | Unit test / executed locally |
| Venkata/SCINET operations and an independent voice identity bridge | Outside this BCC consolidation | NOT verified by this repair |

The generated schema also publishes Venkata/SCINET operations. Their presence
provides no additional access approval or claim of testing. A CLI authorization message can also result from local transport/policy refusal.
Inspect the fixed broker diagnostic categories before asking the owner to log
in again. The detailed consolidation record contains active controls and rollback.
