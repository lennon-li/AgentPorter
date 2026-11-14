# ChatGPT operations on BCC / B6

Updated 2026-11-13 after the ChatGPT audit. This manual describes the activated
BCC consolidation and its corrected isolation/interface guarantees.
For REST/Actions, the running gateway `/openapi.json` is authoritative: 31
advertised operations with `bcc_` operation IDs. For MCP, use the running
`tools/list` input schemas: the public gateway advertises 55 tools, including
`git_push`. MCP wire names are unprefixed; a ChatGPT connection may display
`bcc_` aliases. REST and MCP are separate catalogs. The old saved OpenAPI file
is historical evidence, not proof of the current connection. Keep the existing connection's API key
in its authentication header, never in prompts, URLs, files, or job packets.

## Generation 16 deployment status (2026-11-13)

Generation 16 is active on BCC. The sealed rollout exited 0 and the post-rollout
host receipt verified the gateway and worker release seals, current PIDs and
fingerprints, root/worker UID bindings, shared CLI and native-daemon inode
parity, updater state, and all 38 configured workspaces. Protected-state inspection
confirms the rollback rehearsal passed, admissions were released, and the
discovery timer was restored. After renewed temporary administrator access, the
parent finalized the protected local verification receipt and current-release
pointer for generation 16. After owner-reported external verification and fresh
host cleanup reconciliation, the protected phase is `accepted` for the stated
repair scope. Local post-release checks returned HTTP 200,
passed 88 portable tests, confirmed dispatch telemetry
was absent from the private Git baseline, and freshly compared 31 REST
operations with 55 MCP tools across seven critical schemas. Commit and push
probes returned `POLICY_DENIED`, `LOCKED`, and `executed:false`.

These are authenticated local BCC results. After a fresh post-reset Qman
collection showed available capacity, Jax job
`rjob_a6cad7616d73a3f531072c4dcc2ce6ec` completed read-only verification in
14.31 seconds with exit 0 and 88 portable tests passed. The requested/configured
model and native CLI header matched `gpt-6.1-terra`, low effort; the API's
provider-resolved model remains `unknown`. Canonical Git state and existing
work were unchanged. The current local receipts are in
`artifacts/bcc-astra-fixes-20261113T232839Z/`.

The owner subsequently reported actual external ChatGPT verification, including
completed Jax job `rjob_c0161319000040008000000000000001`, exit 0 in 31.1 seconds,
and 88 portable passes in both ordinary and delegated execution. The parent
reconciled that same job and independently checked host cleanup: inactive relay,
released admission, no leader/process group, removed transaction, and no worker
job resource envelopes remaining. The public API still exposes no separate
successful cleanup receipt. The external report did not independently rerun
host-only custody, updater, database or publication checks; local evidence for
those claims remains distinct. Provider-resolved model metadata is still
`unknown`. External and follow-up receipts are in
`artifacts/bcc-external-gen16-acceptance-20261113/`.

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
policy enforce scope independently of the task text. Native host authentication stores, the host credential socket and unrelated
host home directories are not mounted. Git history has a different guarantee: a
supervised BCC job sees a private Git metadata copy containing the repository’s
real objects, refs, HEAD and stash history. It is not synthetic history and does
not hide repository history from an authorized repository worker. Direct
`git cat-file` reads can succeed. Read-only jobs receive a read-only private
view; writable jobs can change private Git state, but unapproved HEAD/ref/stash
changes cannot cross the publication boundary. Host Git configuration is
replaced by a clean read-only configuration with hooks disabled; host hooks and
linked-worktree administration are removed from the private view. External
object alternates, common Git directories and linked-worktree `.git` files
fail closed. A conventional repository with a missing, malformed, or incomplete
`.git` layout is rejected; every admitted conventional `.git` directory gets a
private metadata view. Root `agent-dispatch` append-only telemetry is excluded
from the private Git baseline because it is job telemetry rather than repository
history; the independent HEAD/ref/stash and Git authority checks remain active.
Git metadata outside a conventional `.git` path, including an arbitrarily named
nested bare Git directory, is treated as ordinary workspace content and is
outside this selected-repository metadata guarantee. Root Git state and ordinary
files remain unchanged when an unapproved history change is rejected. This is a
mutation/publication boundary, not a confidentiality boundary for the selected
repository’s object database.

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

In the 2026-11-13 generation 16 check, the live Jax primary five-hour window
showed 0% remaining and the weekly window 84% remaining. Its observed reset was
2026-11-14 00:54:55 UTC (2026-11-13 19:54:55 America/New_York). The supported
terminal no-model live collector also passed for Jax with two windows; Phil's
terminal collector passed with three windows. The earlier Jax terminal probe
used unsupported `--model`/live options and was a CLI syntax diagnostic, not a
provider failure. Neither terminal collection used the Qman database or made a
model call. No Jax model dispatch was launched while the primary window was
exhausted. At 2026-11-14 00:55:20 UTC, fresh no-cache B6 quota showed 100%
primary and 84% weekly capacity. The subsequent single Jax job completed the
88-test portable selection and private Git-view checks successfully; see
`jax-postreset-acceptance.json` in the generation 16 evidence directory. This
proves that local execution, not general model entitlement. The later
owner-reported external Jax execution is recorded above. Any further dispatch requires fresh quota and must retain
the authorized account and model.

## Approval and Git publication

Lennon selected **approval in this conversation and owner-run Git**, replacing
the browser signer requirement. B6 `git_commit` and `git_push` remain LOCKED.
Worker booleans, ordinary write authority and approval prose cannot unlock them.
REST advertises `bcc_git_commit`, which is denied under this policy; REST
OpenAPI advertises no push operation. MCP advertises both `git_commit` and
`git_push`, and both are denied. A legacy authenticated REST push route also
returns 403; its absence from OpenAPI does not imply no handler exists. Raw HEAD/ref/stash changes and commits after
an approved pull cannot bypass the workspace publication boundary.

After an edit, show the owner the exact diff and proposed commit message. The
owner explicitly approves, then runs Git locally. Push requires separate owner
approval and an owner command. An agent-run command is not an owner-run command.
A text or voice instruction can express the same bounded edit intent; this does
not claim an independent voice identity bridge or create a signed B6 Git receipt.
Do not request browser key enrollment for this selected workflow.

`bcc_git_pull`, `bcc_git_add` and `bcc_git_checkout` remain subject to their own
schemas and effective policy; their presence is not blanket Git authority.

## REST and MCP argument contracts

Refresh discovery after a deployment. Do not use the saved REST schema to infer
MCP tool availability. Fresh comparison covers dispatch, Qman, commit, fetch,
pull, add and checkout; shared fields, required arguments, defaults, types and
nested pattern/length constraints match. MCP dispatch IDs now use the same
lowercase 32-hex pattern as REST. Repository selectors are bounded to 256
characters and local branch selectors to 1024 on both interfaces.

| Operation | REST | MCP |
| --- | --- | --- |
| Dispatch | Workspace ID in URL path; body has task/agent and optional request ID | Required `workspace_id`, task and agent arguments; same optional request ID |
| Live Qman | `GET /api/v1/qman/consult`; workspace is fixed to `qman` | Required `workspace_id:"qman"`; same provider/profile/model/live/cache parameters |
| Commit | Advertised POST route; policy returns 403 | Advertised tool; structured `status:"denied"`, `executed:false`, `error.code:"POLICY_DENIED"` |
| Push | Not advertised by OpenAPI; legacy direct handler denies requests | Advertised tool; same explicit structured denial |

A valid locked request, including `prepare_only:true`, returns the stable code
`POLICY_DENIED`, mode `LOCKED`, action name and reason `action_locked` before
repository access. REST Git handlers return these fields in `detail`. MCP
returns an ordinary protocol result with structured `status:"denied"`,
`executed:false` and `error` containing those fields, plus the same JSON in text.
`isError` is false because the request was understood; **the Git action did not
execute**. Check `status` and `executed`, not just transport success. This avoids
a client adapter translating every MCP tool exception into `INVALID_ARGUMENT`.
Success output keeps its existing validated result schema, extended with the
explicit denial variant. REST remains HTTP 403. Malformed arguments remain
validation errors.
The private worker reports its own actual catalog (54 tools; no public Qman
consultation tool). Do not use that internal catalog as the public gateway list.

## Run verification with the scoped Python runtime

The system `/usr/bin/python3` remains Python 3.10.12. The project's host `.venv`
is intentionally masked inside jobs. Use `bcc-python` (Python 3.13.18) or
`bcc-pytest` (pytest 9.1.1) inside ordinary execution and delegated workers.
They resolve under `/opt/agentporter/verification`, a read-only, root-owned,
code-only runtime. It contains no native HOME, credential store, editable `.pth`
file or project environment mount. Jobs do not install packages.

For a quick check, use `exec_run` in `agentporter` with:

```json
{"argv":["bcc-python","-B","-c","import sys,pytest; print(sys.version.split()[0], pytest.__version__)"],"timeout_seconds":30}
```

For portable fixture checks, use the selection in
`scripts/bcc-scoped-verification.py`. Its ordinary and Jax executions each
passed 88 tests, exit 0. Native sandbox-launch tests require the host supervisor;
the outer worker's namespace/ownership restrictions are retained. In
particular, a credential-alias test that prepares another native sandbox is
excluded from this portable selection and passes in the host suite. Do not
relax confinement to make nested native tests run.

Run the full focused security selection **on BCC's host**, using the host
`.venv/bin/python`, `AGENTPORTER_TEST_BWRAP=/opt/agentporter-bcc/bin/bwrap` and
`scripts/run-bcc-audit-tests.py`. Supply a fresh `--basetemp` and a `--receipt`
path. It covers consolidation, Qman contracts, shared CLI, credential broker and
lease, Git policy, publication parity and the new regressions. The fresh audit
record reports collected/passed/failed/skipped counts and distinguishes an
optional module collection skip from an executed test skip.

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
The Copilot credential validator rejects conflicting legacy account spellings and
accepts the owner-qualified token key and record shape used by the native store.
The producer binds the lease to the enrolled account; the receiving broker
canonicalizes that identity before issuing bounded access.

## Evidence and limits

The generation 16 claim-by-claim matrix, deployment, exact incremental diff,
rollback command, owner-reported external acceptance and repeatable spot-check calls are in
[`BCC_ASTRA_FIXES_2026-11-13.md`](BCC_ASTRA_FIXES_2026-11-13.md).
The earlier generation 15 audit is preserved in
[`BCC_CHATGPT_AUDIT_2026-11-13.md`](BCC_CHATGPT_AUDIT_2026-11-13.md).
The following receipts predate this audit unless that matrix explicitly reruns
a check; reading a prior receipt does not make it fresh.


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
