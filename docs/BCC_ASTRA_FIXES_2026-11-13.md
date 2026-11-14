# BCC Astra findings repair, generation 16

**Status: deployed; local controls verified; final acceptance remains pending.**
The sealed generation 16 controller exited 0 and the post-deployment host/live
receipts confirm generation 16 is active. After the owner renewed temporary
administrator access, the parent finalized the protected local verification
receipt and current-release pointer. Fresh protected-state inspection confirmed
the rollback rehearsal, released admissions, restored discovery timer, and
healthy generation 16 services. The protected phase remains
`active_pending_live_acceptance`. The incremental `repair.diff` and
`final-preservation.json` record 14 session-owned changed paths, 111 untouched
preexisting dirty paths, and preserved `.trash/`, branch, HEAD, and unstaged index.
After the observed quota reset, Jax completed a real read-only verification job
with exit 0 and 88 portable tests passed. External ChatGPT confirmation remains
outstanding. Do not describe this repair as fully accepted or every Astra
finding as externally verified.

## Deployed change and seals

Generation 16 overlays only these four runtime modules onto the sealed
`consolidation-20261113-15-{gateway,worker}` packages:

- `agentporter/agents/credential_broker.py`
- `agentporter/sandbox/workspace_transactions.py`
- `agentporter/sandbox/git_snapshot.py`
- `agentporter/sandbox/workspace_git_recovery.py`

The candidate manifest SHA-256 is
`4ee823ae129ffce259540666344f82f8a03b84be5c2d8c37c8a33fc8fe3346eb`;
normalized controller bootstrap SHA-256 is
`5e09c202198afa4372501976cfebce30a6c5ee8530eee343071801f6bb958587`; sealed
controller SHA-256 is
`1293eb96b035b63621c70c6a89051851ab4f37a2b318d8e61e1803059a9e56c4`. The
strict rebuilt candidate manifest was byte-identical to the originally tested
candidate. The rollout used the pinned library and retained its protected
preimage, seal, custody, and allowlist checks.

`activation-result.json` records exit code 0. `post16-host.json` confirms the
active gateway at
`/opt/agentporter-bcc/releases/consolidation-20261113-16-gateway` (PID 862094,
fingerprint `6746e3cc6706cc29e6cfdb339189d6ab587ac0965180cea4d75eee9d5a2826a9`)
and worker at
`/opt/agentporter-bcc/releases/consolidation-20261113-16-worker` (PID 862093,
fingerprint `1147947d90bb44b90aaca95af379c4b67a1d711531f6d310d254c17315001de8`).
Both seals verified. Protected-state inspection confirms the rollback rehearsal,
released admissions, and restored discovery timer. The protected generation 16
`LOCAL_VERIFICATION.json`, `status.json`, and
`/var/lib/agentporter-bcc/consolidation-current.json` now record generation 16;
the earlier pointer is saved in the control directory as
`previous-consolidation-current.json`. See `local-finalization-result.json`.
The active controller phase remains `active_pending_live_acceptance` because
external ChatGPT confirmation is outstanding. The post-fix Jax model-response
and delegated Git/runtime checks passed after the observed quota reset.

The controller now persists `service_stop_intent` before service stops. If an
exception occurs after that intent, it restores even when no config snapshots
exist, starts and verifies gateway, worker, auth, and Qman before releasing
admissions. Manual rollback and rehearsal use the same ordering. The exact
protected rollback command, if needed, is:

```sh
/opt/agentporter-bcc/releases/consolidation-20261113-16-worker/venv/bin/python -I -B \
  /var/lib/agentporter-bcc/consolidation-20261113-16/rollout.py --rollback
```

No CLI updater or account-selection update was part of this repair. The selected
CLI and native daemon inode checks passed in `post16-host.json`.

## Fix claims and scope

The Git-view repair rejects missing, malformed, or incomplete conventional
`.git` layouts and gives each admitted conventional repository a private Git
metadata view. Foreign-owned read-only transactions use a verified owner-mapped
read-only view, without publication access or changing owner-private object
permissions. The original production failure was worker UID 997 unable to read a
valid mode-0400 loose object owned by Yeli UID 2056259175; the owner-side
read-only history check passed. After deployment, the actual UID 997 mapped
projection preflight passed the excluded-path history check with exit 0 and no
provider process or publication view (`jax-worker-mapped-git-preflight.json`).

Snapshot capture excludes root `agent-dispatch` append-only telemetry because it
is job telemetry rather than repository history. Independent Git authority
checks remain active. Git metadata outside conventional `.git` paths—including
an arbitrarily named nested bare Git directory—is ordinary workspace content
outside this selected-repository metadata guarantee. This is a scope
clarification; it does not assert that every Git-formatted filesystem tree is
protected.

The Copilot validator rejects conflicting legacy account spellings and accepts
the owner-qualified key and native token-record shape. The broker binds issuance
to the enrolled account and the receiver canonicalizes it. The final native
format check preserved all four native auth fields and left the native document
bytes unchanged.

## Evidence matrix

| Claim or check | Verified result | Evidence and limit |
| --- | --- | --- |
| Source focused security suite | 587 collected; 586 passed; 0 failed; 2 skipped; exit 0; native sandbox enabled | `source-focused-tests.json` and log |
| Gateway candidate role tests | 150 passed; 0 failed | Role-spelling-only fixture adaptation; no assertions removed |
| Worker candidate role tests | 144 passed; 0 failed; 1 optional Qman module skip | Same tests-only role alias adaptation; no assertions removed |
| Initial unadapted role fixtures | Gateway 143 passed/7 failed; worker 137 passed/7 failed/1 skipped | Generic test-fixture role names did not match deployed aliases. Recorded as failed diagnostic runs; the adapted runs changed only provider/profile spellings. |
| Related Git regressions | 56 passed; exit 0 | `related-git-tests-final.log` and XML; this supersedes the earlier 53/3 assertion-message run |
| Rollout recovery fault tests | 3 passed | Independent fake-unit run of `test_bcc_astra_rollout.py` |
| Ordinary post-deployment probe | HTTP 200; exit 0; 88 passed; host dispatch telemetry absent | `post16-live.json`; authenticated local BCC, not external ChatGPT. Real history object readable; isolated metadata inode, hooks disabled, no host HOME, credential socket, or native store reads. |
| Host/service/seal checks | Passed; root and worker UID bindings, shared CLI selection and daemon inode parity, timer/updater and 38 configured workspaces verified | `post16-host.json`; gateway/worker active PIDs and fingerprints above |
| REST/MCP parity | 31 REST operations; 55 MCP tools; 7 critical schema comparisons passed | `post16-interface-parity.json`; fresh local catalogs |
| Commit/push denial | Both returned `POLICY_DENIED`, mode `LOCKED`, `executed:false` | `post16-live.json`; no publication occurred |
| Credential issuance | Actual worker UID 997; Jax/Liz/Prof native login status and Ming/Phil issuance passed; no model calls; no refresh authority delegated; native store bytes unchanged | `post16-credential-issuance.json`; account identifiers were not emitted |
| Copilot native compatibility | Four native auth fields preserved exactly; native bytes unchanged | `copilot-native-format-compatibility-final.json` |
| Live Prof/Luna release-prep Qman | Unavailable: `live_quota_capability_not_authorized`; no provider process and no cached fallback | `closure-docs-qman.json`; no quota observation |
| Live Jax/Terra Qman before reset | Fresh live result; no cache/database; primary five-hour window exhausted (0% remaining), weekly window 84% remaining | `post16-jax-quota.json`; reset hint at 2026-11-14 00:54:55 UTC / 2026-11-13 19:54:55 America/New_York. Historical pre-reset observation, not current capacity or model entitlement. |
| Live Jax/Terra Qman after reset | Fresh collection at 2026-11-14 00:55:20 UTC; primary 100% remaining and weekly 84%; no cache/database | `jax-postreset-quota.json`; session identity checked; persistent binding and model entitlement remain unverified by Qman. |
| Post-fix Jax model and delegated checks | Completed; exit 0; 14.31 seconds; 88 passed, 0 failures/errors/skips; Git private-view checks and canonical-state preservation passed | `jax-postreset-acceptance.json`; job `rjob_a6cad7616d73a3f531072c4dcc2ce6ec`. Requested/configured model and native CLI header are `gpt-6.1-terra`, low effort; provider-resolved model remains `unknown`. This was actual local production delegation, not external ChatGPT. |
| Terminal native Qman collections | Supported no-model live Jax invocation passed with 2 windows; Phil live-first invocation passed with 3 windows; DB and sidecars unchanged; 0 model calls | `post16-native-qman-jax-supported.json`, `post16-native-qman.json`. The earlier Jax CLI diagnostic exited 2 on unsupported `--model`/live options (`post16-native-qman-jax-diagnostic.json`); this was an invocation syntax issue, not a provider failure. |
| External ChatGPT acceptance | Pending | Parent's four safe acceptance calls have not yet been confirmed here. Local authenticated BCC checks do not establish external connection behavior. |
| Protected deployment records | Finalized; services and package seals rechecked | `local-finalization-result.json`; phase remains `active_pending_live_acceptance`, without claiming the outstanding live checks passed. |
| Final source preservation diff | 14 session-owned paths; 111 preexisting dirty paths unchanged; no foreign changes | `repair.diff` and `final-preservation.json`; `.trash/`, current branch/HEAD, and unstaged index preserved. |

The Astra recheck in `astra-fix-review.md` cleared the controller recovery
blocker after reviewing the corrected stop-intent and restore paths. That is a
bounded source/controller review, not proof of external ChatGPT acceptance.

## Post-reset Jax result and remaining external verification

No Jax model dispatch was launched while the primary window was exhausted.
After the reset hint passed, a new live B6 consultation observed 100% primary
and 84% weekly capacity with no cached fallback or database access. Its Terra
API price card is dated reference data, not a subscription charge estimate or
entitlement proof. The exact consultation selectors were:

```json
{
  "provider": "codex",
  "profile": "jax",
  "model": "gpt-6.1-terra",
  "live": true,
  "allow_cached_fallback": false
}
```

A single read-only production dispatch then used Jax, `gpt-6.1-terra`, low
effort, `read_only:true`, `allow_commit:false`, and `allow_push:false`. Job
`rjob_a6cad7616d73a3f531072c4dcc2ce6ec` completed in 14.31 seconds with exit 0
and a real agent response. The probe ran 88 portable tests successfully and
verified real Git object reads, private HEAD inode, canonical ref equality,
disabled hooks, and absence of host hooks/worktree administration/alternates,
host home, and the tested credential socket. No cleanup error was reported.
Independent before/after checks confirmed unchanged canonical HEAD, refs, HEAD
inode, branch, tracked diff, Git status, and unstaged index.

`jax-postreset-plan.json`, `jax-postreset-quota.json`,
`jax-postreset-dispatch.json`, `jax-postreset-status.json`,
`jax-postreset-result.json`, and `jax-postreset-acceptance.json` retain the
request, observation, execution, and parent verification. The native CLI header
matches the requested/configured model; the API's provider-resolved model is
still `unknown`, so no independent provider model attestation is claimed.
The probe's `model_calls_from_probe:0` refers to its Python checks; the
surrounding Jax agent did execute a model request. Native sandbox-launch tests
were not run inside that delegated namespace. External ChatGPT confirmation
remains pending.

Refresh the actual ChatGPT connection's tool discovery, then run these four
safe acceptance calls, using its discovered `bcc_` aliases if present:

1. `server_deploy_info({})`. Expect generation 16, matching loaded/disk
   fingerprints, and `stale:false`.
2. `exec_run({"workspace_id":"agentporter","argv":["bcc-python","-B","-c","from pathlib import Path; import sys,pytest; print(sys.version.split()[0],pytest.__version__,not Path('/workspace/.git/agent-dispatch').exists())"],"timeout_seconds":30})`.
   Expect exit 0 and `3.13.18 9.1.1 True`.
3. `git_commit({"workspace_id":"bcc-astra-fix-nonexistent","message":"DENIAL AUDIT ONLY","prepare_only":true})`.
4. `git_push({"workspace_id":"bcc-astra-fix-nonexistent","prepare_only":true})`.

Both Git probes must return `status:"denied"`, `executed:false`,
`error.code:"POLICY_DENIED"`, `mode:"LOCKED"`, and `reason:"action_locked"`.
The deliberately nonexistent workspace prevents either probe from selecting
existing work. These calls verify the external connection; the separate Jax
model-response test above already passed through the local production gateway.
