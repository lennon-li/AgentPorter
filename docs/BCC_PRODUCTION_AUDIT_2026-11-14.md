# BCC production audit — 2026-11-14

## Current result

**Generation 17 is active; full production acceptance remains incomplete.**
Jax's personal login was restored and a fresh post-deployment Jax job succeeded.
Ming's matching native identity currently has expired access; owner renewal is
pending. Actual external ChatGPT acceptance after generation 17 is **NOT verified**.
Historical generation 16 acceptance is retained with its original scope.

No credentials or account identifiers are included here. Jax personal and Prof
academic research are separate accounts. Their existing enrollment policy was
preserved, as were Liz's separate binding, access-only custody, Git locks, the
owner-run Git workflow and paused/excluded identities.

## Claim-by-claim verification

Host receipts below are under
`/home/yeli/repos/AgentPorter/artifacts/bcc-production-repair-20261114/`.
Source/candidate test receipts are under the same relative artifact directory
in `/tmp/agentporter-bcc-publication-20261113`. Reading an older receipt does not
make it a fresh test. Every test listed as fresh ran on 2026-11-14.

| Claim | Test and evidence | Result / verification class | Remaining limitation |
| --- | --- | --- | --- |
| External audit reached production | Owner-pasted ChatGPT audit: generation 16, 55 tools, 39 existing workspaces, 88 portable passes / 3 deselected | Historical external observation for this repair | Generation 17 external ChatGPT checks pending |
| Initial Jax launch refusal is explained | Correlated request `d0141416000040008000000000000001`, worker row `job_051a306d2c645168a1de3d65`, safe worker log category `credential_broker_refused`; native binding comparison | Fresh protected host diagnosis; exit 1 before provider launch, no output | Generic public `launch_rejected` alone did not identify the originating check |
| Jax and Prof remain separate | Owner completed Jax personal native device login; `_read_native` compared each current native document with its original enrollment; all three Codex bindings distinct | Fresh host execution; Jax, Liz and Prof match original enrollments | No identifiers emitted; Qman persistent identity assurance remains separate |
| Original ordinary runtime transient is explained | Gateway journal `flock` EAGAIN at 17:00:46 while `job_93b2ce7e6cc14130829f0b66` ran until 17:00:50 | Fresh host diagnosis of transaction contention | External runtime call was repeated once successfully; original failed Jax dispatch was not retried |
| Explicit workspace-busy diagnostics | `generation17-busy-live.json`: a real async holder; MCP `exec_run` and `exec_start`; REST run/start; holder completed exit 0; subsequent runtime call exit 0 | Fresh local authenticated live execution; MCP normal result / `isError:false`; REST 409; code `WORKSPACE_BUSY`, no launch/execution, retry hint 3 seconds | Live helper records JSON hint; HTTP Retry-After header separately covered by unit tests |
| Runtime release matches disk | `fresh-shared-installation-generation17.json`; protected seal checks and live fingerprint | Fresh host execution: gateway PID 1932718, worker PID 1932717, both generation 17 seals valid | PID is an observation, not a permanent identifier |
| REST and MCP are distinct, precise catalogs | `generation17-interface/live-interface-after.json`, fresh `/openapi.json` and MCP `tools/list`; dispatch, Qman, commit/fetch/pull/add/checkout field/default/type parity | Fresh local live: 31 REST operations, 55 MCP tools, seven parity checks passed | MCP-only push has no corresponding REST endpoint; no post-deployment external discovery yet |
| Commit/push remain locked | Same fresh live interface receipt: both actions, normal and prepare-only, nonexistent audit workspace | Fresh local live: `POLICY_DENIED`, `LOCKED`, `executed:false`; MCP normal data, REST commit 403 | Does not authorize publication or replace isolated bypass tests |
| Scoped verification runtime works in Jax | `generation17-jax-result.json`, public job `rjob_fe2043fca168fa8e345a6adc8ebd60b0` | Fresh local live dispatch, completed exit 0 in 23.308 s; delegated report Python 3.13.18 / pytest 9.1.1, 91 cases: 88 passed, 3 deselected, zero failed/skipped; one dependency deprecation warning | Command output is delegated report; API `actual_model:unknown`; requested/configured Terra is not resolved-model proof |
| Repaired Jax also worked before cutover | `restored-jax-live-result.json`, `rjob_93d53e1bdd71573ee9c3b3700a2b54d7` | Fresh local generation 16 job after login restore: exit 0, 19.684 s, 88 passed / 3 deselected | Separate run from post-cutover generation 17 job |
| Completed job cleanup | `generation17-jax-host-reconciliation.json`, `generation17-cgroups.json`; worker DB, relay DB, process/filesystem/cgroup inspection | Fresh host execution: process absent, transaction absent, admissions 0, relay completed/inactive, zero job envelopes in gateway and worker cgroups | Specific to observed jobs; public successful result has no separate cleanup field |
| Full source regression gate | `source-full.xml` | Executed locally: 2,937 collected, 2,928 passed, 9 skipped, zero failed/errors, exit 0; one Starlette deprecation warning | Precedes addition of the two separately tested rollout fault cases |
| Rollout fault handling | `rollout-faults-parent.xml`; optimized Python rejected before protected reads; journal-save failure still triggers recovery | Unit tests: 2 collected/passed, zero failed/skipped, exit 0 | Simulated failures; normal guarded rollback rehearsal was also executed live |
| SDK busy/success and policy compatibility | `busy-parent.xml`, real MCP protocol and REST/OpenAPI fixtures, real flock tests | Executed locally: 48 collected/passed, zero failed/skipped, exit 0 | Overlaps the full source suite; counts must not be added as unique tests |
| Actual production-derived package regression | `candidate-gateway-tests.xml` / candidate-worker receipt; `runtime-fixture-bridge/results-final.xml` and manifest | Executed locally: 8 passed per role; 90 worker security cases passed, zero failures/skips, exit 0 | Production uses named identities; bridge translates only fixture aliases and synthetic helper setup. Assertions unchanged. Earlier fixture alias / stdin-spawn failures were corrected in the test harness, not suppressed |
| Real history is readable but canonical metadata is isolated | Production-derived 90-case selection includes consolidation, Git views/metadata, incomplete/foreign layouts and publication mutation fixtures; prior ordinary/delegated history probes retained | Fresh host fixture tests passed; documented guarantee is mutation/publication isolation, not repository-history confidentiality | Fresh gen17 external Git probes pending; arbitrary nested bare Git directories remain ordinary workspace content |
| Shared CLI and daemon selection | `fresh-shared-installation-generation17.json`: immutable manifest/file hashes, terminal launchers, worker selections and native daemon executable inodes | Fresh host execution passed for 39 configured existing workspaces; Codex 0.169.0, Claude 2.1.325, Copilot 1.0.112, OpenCode 1.19.5, Agy 1.5.9 | Version checks did not dispatch Wei or Argie; no actual update performed |
| Native access custody and no writeback | `fresh-native-custody-generation17.json`: six real Codex access snapshots and Phil snapshot as worker UID 997; hostile fixture edits followed by lease finish; before/after all five native auth bytes compared in memory | Fresh host execution passed for Jax/Liz/Prof/Phil; native stores unchanged; Codex refresh authority excluded; no model calls | Ming issuance blocked before access creation; complete five-provider live custody acceptance pending |
| Stale/changed identity fails closed | Production-derived credential broker/lease security fixtures; actual Ming preflight | Fresh host fixture tests passed; actual expired Ming access refused with binding still matching enrollment | Ming native renewal requires owner; do not lower the 1,260-second threshold |
| Shared updater privilege/credential boundaries | `fresh-updater-generation17.json`; timer/service effective settings and installed runner; shared-installation check covers disabled native updaters and removed updateCLI cron | Fresh configuration inspection: timer active at 02:00 America/New_York; strict filesystem, no-new-privileges, native auth paths inaccessible, package staging under unprivileged UID | No CLI update triggered merely to verify configuration; stored last-update success is not a fresh update |
| Terminal Qman and DB preservation | `fresh-terminal-qman.json`: actual terminal live Jax/Phil calls, DB/WAL/SHM bytes/inode/mtime/ownership before/after | Fresh local live collectors: both exit 0, `live:true`, `mode:live_first`, no DB use, unchanged DB/sidecars, no model/update | Initial wrapper expected literal `live`; parent validated native `live_first` from saved fresh results without repeating collectors |
| Jax capacity before post-cutover dispatch | `generation17-jax-quota.json`: exact Codex/Jax/Terra live request, no cached fallback | Fresh local live at dispatch: five-hour 96%, weekly 83% remaining, source codex_app_server_0.169.0 | Snapshot expires; persistent identity binding and general model entitlement remain unverified by Qman |
| Prof quota remains unavailable by policy | Fresh exact Prof/Luna consultation | Live refusal `live_quota_capability_not_authorized`, no cache | Capacity/reset/entitlement unknown; refusal does not permit account substitution |
| Existing work preserved | `original-preservation-baseline.json`, guarded manual preimage and final preservation receipt | Canonical HEAD, index and unrelated files preserved; only manual and new dated audit document intentionally synchronized | Before/after Jax comparisons do not hash all untracked contents; the final host baseline separately does |

## Exact change and deployment

The source change is confined to five modules:

- `policy_errors.py`: typed `WorkspaceBusyError` and normal structured MCP busy results; successful dictionary metadata and existing Git denial behavior preserved.
- `sandbox/workspace_transactions.py`: translate actual nonblocking lock contention and close the failed lock descriptor safely.
- `server.py`: REST HTTP 409 plus `Retry-After: 3` for the typed busy condition.
- `rest/routers/exec.py` and `rest/schemas.py`: publish the 409 response contract for both execution routes.

Two new test modules cover contention, protocol envelopes, successful metadata,
optimized-interpreter refusal and recovery after a journaling error. The
preparer and guarded controller are retained for review and rollback.

**Installed release and branch source are not fully identical.** Generation 16's
installed `production_relay.py` and `tools/jobs.py` contain existing durable
queued admission/RelayDispatch behavior differing from branch `a27787e`.
Generation 17 cloned the exact installed releases and applied only five reviewed
afterimages per role. Those relay/JobManager bytes, shared CLI references and
credential/account policy were preserved. Do not bulk install the branch source
as a substitute for this overlay. `candidate-overlay.json` records the proof.

Candidate manifest SHA-256:
`3f824cb9f6780f42981c43962f0462b772f8fdff16294c84b65fa466a8a65d37`.
Hardened bootstrap seal:
`4856376253682318dbf65814c366b661c31b4251eabc87036a3322671024822a`.
Controller file SHA-256:
`a17ea085875185c6aba6b768b309de2739b92901224e39baa18cc6d1951ac7a8`.

The guarded rollout exited 0, restarted gateway/worker plus broker/Qman with
new release paths, rehearsed restoration of generation 16, reactivated 17,
verified profiles and seals, released admission guards and restored discovery.
No additional restart is required for these already-active source changes.
The protected control directory is
`/var/lib/agentporter-bcc/consolidation-20261114-17`; its phase remains
`active_pending_live_acceptance`, with no guards retained. The current pointer
and local verification record must retain the outstanding Ming and external
acceptance limitations; historical gen16 acceptance is not copied as gen17 proof.

## Rollback

Use the sealed installed controller, with temporary owner-granted sudo:

```sh
sudo /opt/agentporter-bcc/releases/consolidation-20261114-17-worker/venv/bin/python -I -B /var/lib/agentporter-bcc/consolidation-20261114-17/rollout.py --rollback
```

It acquires operation locks/admission guards, pauses discovery, restores recorded
systemd configuration and the prior current pointer, starts and verifies the
baseline gateway/worker/broker/Qman, then releases guards and restores discovery.
It does not undo the owner's native login, reset canonical work, update CLIs or
weaken policy. Rollback guard setup failures remain fail-closed for operator
inspection; do not bypass retained guards. Source rollback is a normal reviewed
Git revert of the published repair commit, never reset/force-push of existing work.

## Concrete external ChatGPT acceptance

Refresh BCC discovery. Use actual discovered schemas; `bcc_` is a client alias,
while MCP wire names are unprefixed. Keep API keys in the connection header.

1. `server_deploy_info({})`: expect generation 17, matching loaded/disk fingerprints, `stale:false`.
2. `get_capabilities({})`, `list_workspaces({})`: expect 55 MCP tools, commit/push `LOCKED`, 39 existing paths; counts may change only with a separately recorded configuration change.
3. `git_commit({"workspace_id":"bcc-policy-audit-nonexistent","message":"DENIAL AUDIT ONLY","prepare_only":true})` and `git_push({"workspace_id":"bcc-policy-audit-nonexistent","prepare_only":true})`: expect `status:"denied"`, `executed:false`, `error.code:"POLICY_DENIED"`, reason `action_locked`, normal MCP data.
4. `exec_run({"workspace_id":"agentporter","argv":["bcc-python","-B","-c","import sys,pytest; print(sys.version.split()[0],pytest.__version__)"],"timeout_seconds":30})`: expect 3.13.18 / 9.1.1, exit 0. If another transaction holds the workspace, retain the explicit `WORKSPACE_BUSY` response and reconcile the holder before a new request.
5. Inspect current dispatch/Qman/Git schemas. Compare live REST `/openapi.json` (31 advertised operations, no push) separately with MCP `tools/list` (55 tools). Do not infer parity from saved snapshots.
6. `qman_consult({"workspace_id":"qman","provider":"codex","profile":"jax","model":"gpt-6.1-terra","live":true,"allow_cached_fallback":false})`: verify fresh native windows; quota alone is not execution permission or entitlement proof.
7. With fresh capacity, make **one** read-only Jax dispatch in `agentporter`, fresh 32-hex `request_id`, `agent:"jax"`, `model:"gpt-6.1-terra"`, `reasoning_effort:"low"`, `read_only:true`, `allow_commit:false`, `allow_push:false`, and a task to run the documented portable test selection through `bcc-python`. Set purpose `Generation 17 external production verification`. Poll its exact handle, retrieve output/result and record status, exit/counts and any cleanup limitation. Preserve HEAD/status/diff/index/refs before/after. Do not retry uncertain launches or use Prof as fallback.

The portable selection and its three host-only exclusions are documented in the
operating manual. Deterministic busy testing additionally needs an authorized
bounded `exec_start` sleep holder, followed by run/start probes while it owns the
transaction; expect no execution and the explicit busy envelope, then normal
runtime after holder completion. Do not leave the holder running.

Full acceptance requires Ming's original native renewal, fresh successful
worker-UID Ming issuance with refresh exclusion/no writeback, and the external
generation 17 checks. Wei remains paused; Argie/Agy remediation and Venkata/
SciNet execution remain excluded. No new account or model entitlement is inferred.
