# BCC ChatGPT operating-manual audit — 2026-11-13

The locally verified application is `consolidation-20261113-15` for gateway,
worker, credential broker and Qman. The shared agent CLI selection is unchanged.
Prof stayed in the current account and preserved the original dirty `main`
checkout. No repository branch, commit or push was created in this audit.
Existing `.trash/` entries belong to the repository owner and were retained.

Fresh evidence is under `artifacts/bcc-chatgpt-audit-20261113/`. These are new
executions, separate from the earlier consolidation receipts. Raw credential
values, token fingerprints and native account identifiers are not emitted.

## Findings and corrections

The old manual's claim that raw Git history was inaccessible was false. The
writable job view was already private, but contained genuine repository
history. Read-only workers could see canonical metadata read-only; private
copies also included owner hooks and linked-worktree administration. Both
supervised modes now use private Git metadata, with clean configuration and no
host hooks/worktree administration. History content remains readable because
repository Git inspection is an intended capability. This does not claim to
hide historical/unreachable objects inside the selected repository's object
database. External alternates, shared/common Git layouts and linked-worktree
metadata files fail closed. Raw changes to history still cannot publish.

The public REST schema advertises 31 operations. The actual public MCP gateway
advertises 55, including locked `git_push`; the internal worker advertises 54.
Catalogs were fetched from running services, not inferred from old snapshots.
The worker lacked an `unpublished_actions` diagnostic: it now computes the
catalog from actual MCP registration. MCP dispatch ID patterns and Git selector
length bounds now match REST. Valid commit/push refusals were previously
sanitized by the MCP SDK as unexpected exceptions. The first fix made the reason visible, but actual external ChatGPT testing
showed that its outer adapter still classified MCP tool errors as
`INVALID_ARGUMENT`. Generation 14 therefore returns an explicit MCP data result:
`status:"denied"`, `executed:false`, `error.code:"POLICY_DENIED"`, mode `LOCKED`,
reason `action_locked`. The protocol request succeeds; the Git action never
executes. The validated output schema includes both successful Git results and
this denial variant. REST still returns structured HTTP 403, including
prepare-only requests.
No action mode was made more permissive.

A sealed Python 3.13.18 / pytest 9.1.1 code-only runtime is mounted read-only at
`/opt/agentporter/verification`, exposed as `bcc-python` and `bcc-pytest` in both
job types. System Python and the masked host `.venv` were not repurposed. No
packages are installed during a job and no credential/HOME mount was added.

## Claim-by-claim matrix

| Claim | Test | Fresh evidence | Result / kind | Remaining limitation |
| --- | --- | --- | --- | --- |
| Git metadata is private, but real history is readable | Direct HEAD object read, HEAD inode comparison and refs equality in ordinary execution and Jax | `ordinary-execution15.json`, `jax-scoped-tests.json`, `live-scoped-summary.json` | PASS — local live execution | This permits reads of the selected repository's real object database; it is not synthetic history |
| Canonical refs, stash and ordinary files cannot change through unapproved worker history | Disposable commit/raw-ref/stash and post-pull mutation probes; complete canonical metadata comparison across both live runs | `final15-source-tests.log`, `frozen13-*.log` plus targeted `final15-*.log`, `live-scoped-summary.json` | PASS — native fixtures and local live execution | Private writable Git state can change before publication rejects it |
| Host hooks/configuration/worktree administration do not enter the delegated Git view | Fixture HEAD/stash/object reads with seeded host hook and detached worktree; live absence/config checks | `test_bcc_git_views.py`, same fresh live receipts | PASS — native fixtures and local live execution | Normal repository worktree files are in scope |
| External alternates/common layouts/linked worktree metadata fail closed | Disposable alternates and `.git` pointer fixtures; existing snapshot checks | `final15-source-tests.log`, `frozen13-*.log` plus targeted `final15-*.log` | PASS — native fixtures | These Git layouts remain unsupported; select a conventional registered repository |
| Host home and credential socket are absent | Exact path probes in ordinary execution/Jax | Both scoped receipts | PASS — local live execution | Job-local provider access is intentionally provisioned for the selected worker |
| Public REST and MCP are separate, accurately described interfaces | Fresh `/openapi.json`, MCP `tools/list`, capabilities comparison | `rest-catalog-after.json`, `mcp-catalog-after.json`, `live-interface-after.json` | PASS — local live authenticated REST/MCP | External ChatGPT discovery must be refreshed separately |
| Critical argument schemas agree | Compare dispatch/Qman/Git shared fields, required/default/type/pattern/length schema; preserve path-vs-argument adaptation | `live-interface-after.json` | PASS — local live schema comparison | REST fixes Qman's workspace; MCP requires `workspace_id:"qman"`; push is not advertised in REST |
| Locked Git diagnostics are explicit and safe | Valid commit/push, normal and prepare-only, over both interfaces; fixture backend lookup forbidden | `test_bcc_policy_diagnostics.py`, `live-interface-after.json`, `final15-*.log` | PASS — isolated fixtures and local live calls | Invalid arguments remain validation errors; no signer enrollment or unlocked commit backend was added |
| Scoped Python can run relevant portable checks | Execute real pytest in ordinary job and Jax; independently read Jax's canonical receipt | `ordinary-execution15.json`, `jax-scoped-tests.json`, `jax-independent-readback.json` | PASS — 88 tests in each; local live execution | Nested native sandbox-launch tests run on the host, preserving outer confinement |
| Terminal/worker CLI selections and native daemon inodes agree | Rehash shared code/manifest, inspect aliases, actual worker mapping and running daemon executables | `final15-host-installation.json` | PASS — fresh host execution/configuration inspection | Old sealed recovery releases remain unselected |
| Native account bindings remain distinct | Compare enrolled/current bindings in memory; actual worker-UID credential issuance | `final-credential-updater.json` | PASS — fresh host execution | Identity equality is checked locally; no provider account IDs are published |
| Delegation is access-only and cannot write back native credentials | Real UID 997 issuance, native login status without model turns, hostile temporary credential edits, compare all native auth file bytes before/after | `final-credential-updater.json` | PASS — fresh host execution | Native clients retain responsibility for legitimate renewal |
| Stale access and changed bindings fail closed | Synthetic short/expired access, unavailable native authority, changed-account and wrong-UID broker fixtures | `test_credential_broker.py`, `final15-source-tests.log`, `frozen13-*.log` plus targeted `final15-*.log` | PASS — safe fixtures | Actual native accounts were not deliberately expired/switched |
| Shared updater is scheduled with protected custody | Inspect live timer timezone, service protection, credential exclusions, unprivileged staging runner, native daemon preferences and worker startup environment | `final-credential-updater.json`, `final15-host-installation.json`; sealed worker code | PASS — fresh configuration inspection | No actual CLI update was triggered by this audit; configuration inspection is not a vendor-update execution test |
| Native terminal Qman uses shared collectors without changing its database | Direct fresh Jax and Phil collectors, no model turn, compare DB/sidecar identity/bytes before and after | `fresh-native-qman.json` | PASS — fresh host live collection | Existing identity/entitlement/reset-window caveats remain; collection does not prove entitlement |
| Actual external ChatGPT reaches current tools/runtime | Owner ran four acceptance calls | `external-chatgpt-first.json` | PASS for discovery, locks and runtime — owner-reported actual external execution | First denial envelope had outer `INVALID_ARGUMENT`; final owner retest confirms both explicit denied results in `external-chatgpt-final.json` |
| External Git denials retain the explicit policy result | Owner reran both prepare-only calls after discovery refresh | `external-chatgpt-final.json` | PASS — owner-reported actual external execution | Receipt records the fields the owner returned, not an invented raw response |
| Gateway loaded and disk code agree after restart | Authenticated deploy-info, seal checks and expected live PIDs for both roles | `live-interface-after.json`, `final15-host-installation.json` | PASS — local live execution | These calls originate locally, not from ChatGPT |
| Earlier external successes are preserved without relabeling them fresh | Keep same CLI/accounts/route policy; new Jax execution and bounded canonical receipt publication succeed | Prior owner audit plus this audit's live scoped receipts | Earlier five-provider requests/Liz edit/quota/file operations remain owner-reported external evidence | This audit did not repeat every provider model call externally |
| Complete network isolation is not inferred from one failed TCP attempt | Retain namespace/scoped-egress controls and focused provider broker tests | Configuration plus `final15-source-tests.log` | Scoped controls tested; comprehensive external network claim NOT made | The earlier single external TCP refusal alone proves no broader network claim |

The Jax job is `rjob_a0135c9869bc4d8241938556b7c9aedc`, model
`gpt-6.1-terra`, low effort. Live Jax quota was collected immediately before its
one dispatch; no cached fallback, alternate identity/model or uncertain retry
was used. Its receipt was read independently via the file API and compared with
the canonical file. B6's result exposes final worker output rather than a full
provider command trace; that trace is not claimed as observed. The same fixed
probe was also independently executed through ordinary execution.

## Test accounting

| Run | Collected / selected | Passed | Failed / errors | Skipped | Exit |
| --- | ---: | ---: | ---: | ---: | ---: |
| Final source focused suite | 518 items | 517 | 0 / 0 | 2 total: one item and one module during collection | 0 |
| Frozen gateway generation 13 | 156 items / 154 selected | 154 | 0 / 0 | 0; two deselected | 0 |
| Frozen worker generation 13 | 150 items / 148 selected | 148 | 0 / 0 | One optional Qman module collection skip; two deselected | 0 |
| Ordinary portable sandbox run | 88 selected | 88 | 0 / 0 | 0 | 0 |
| Actual Jax portable sandbox run (generation 13 Git/runtime; unchanged by generation 14 envelope fix) | 88 selected | 88 | 0 / 0 | 0 | 0 |
| Final envelope/argument/allowed-commit regression, source and each frozen role | 21 selected per run | 21 per run | 0 / 0 | 0 | 0 |

Source Qman socket contracts run against the gateway's installed Qman module
in the frozen suite; that optional module is absent in the generic source and
private worker. The source's other skip is the optional upstream-bundled Codex helper
fixture (`test_development_runtime.py`), whose historical host package lookup
is unavailable; the actual selected shared CLI/helper is separately checked by
the host/worker verifications. Two provider runtime-name adaptation cases were deselected
only in frozen-package runs; the complete source provider broker/runtime suites
ran, and real provider access issuance was independently checked on the host.
Native sandbox-launch tests are not portable into an already confined job.
The credential-alias native-launch fixture therefore stays in the host suite;
it is explicitly excluded from the portable selection, not marked as a job
pass. Initial failed/debug runs are retained as historical diagnostics. The
final runs above supersede them. This is not a claim that every legacy test in
the repository's broader suite was reconciled or executed.

## Deployment and rollback

Only sealed application overlays were deployed. Generation 11 introduced Git
views, diagnostics and the scoped runtime mount. Generations 12/13 completed
catalog diagnostics and initial schema parity. Generation 14 corrected the external
client denial-envelope classification without changing the Git/runtime views.
Generation 15 uses the REST FieldInfo for shared MCP arguments and validates the
full nested/top-level string, numeric and collection bounds, rather than only
basic types. It changes no Git action authority. Gateway, worker, credential broker and
Qman were restarted using admission holds, production/discovery locks, active
job checks and exact preimage checks. Each cutover rehearsed rollback before
reopening admissions. The active discovery timer was restored. Credential
stores, account selection, action locks and agent CLI selection were retained.

Current protected controller:
`/var/lib/agentporter-bcc/consolidation-20261113-15/rollout.py`.
It can restore the preceding generation, with jobs quiescent:

```sh
sudo /usr/bin/python3.13 -I -B /var/lib/agentporter-bcc/consolidation-20261113-15/rollout.py --rollback
```

For full restoration of the pre-audit application, run the generation 14, then generation 13, then generation 12 and
then generation 11 protected controllers with `--rollback`, in that order.
Generation 11 restores generation 10. The complete pre-audit application rollback
sequence, after the generation 15 command above, is:

```sh
sudo /usr/bin/python3.13 -I -B /var/lib/agentporter-bcc/consolidation-20261113-14/rollout.py --rollback
sudo /usr/bin/python3.13 -I -B /var/lib/agentporter-bcc/consolidation-20261113-13/rollout.py --rollback
sudo /usr/bin/python3.13 -I -B /var/lib/agentporter-bcc/consolidation-20261113-12/rollout.py --rollback
sudo /usr/bin/python3.13 -I -B /var/lib/agentporter-bcc/consolidation-20261113-11/rollout.py --rollback
sudo install -o root -g root -m 0444 /var/lib/agentporter-bcc/consolidation-20261113-15/previous-consolidation-current.json /var/lib/agentporter-bcc/consolidation-current.json
```

Do not skip a controller's expected predecessor or replay earlier historical
controls blindly. After full rollback,
restore `consolidation-current.json` from generation 15's saved
`previous-consolidation-current.json`. The new sealed verification runtime can
remain unused; generation 10 does not mount it. This recovery restores older
behavior, including the original documentation/isolation gaps.

The exact incremental source/doc/test diff is
`artifacts/bcc-chatgpt-audit-20261113/repair.diff`; it compares with the dirty
checkout captured at audit start, not with clean `main`. Existing unrelated
Nida/Qman edits are preserved. Installed service preimages and package seals
remain in the protected generation controllers. Source changes require a new
sealed deployment to affect production; do not edit active sealed releases.

## Concrete external ChatGPT acceptance calls

The initial four steps were run by the owner and reported back from actual
external ChatGPT. Discovery/locks/runtime passed; the denial wrapper required
the generation 14 correction. The owner completed the final denial-envelope retest: both tools returned
`POLICY_DENIED`, mode `LOCKED`, reason `action_locked`, and `executed:false`.
This is owner-reported actual external execution, saved in
`external-chatgpt-final.json`; raw response objects were not pasted. Reading a
stored receipt below does not constitute a fresh execution.
Use the connection's discovered names; MCP wire names below may have `bcc_`
aliases in ChatGPT. Never include an API key in the conversation.

1. Refresh discovery, then `get_capabilities({})`. Expect MCP count 55,
   `git_commit` and `git_push` LOCKED, no unpublished actions.
2. `git_commit({"workspace_id":"bcc-policy-audit-nonexistent","message":"DENIAL AUDIT ONLY","prepare_only":true})`.
   Expect structured `status:"denied"`, `executed:false`,
   `error.code:"POLICY_DENIED"`, `LOCKED`, `action_locked` before any
   repository lookup. The nonexistent fixture selector cannot publish owner work.
3. `git_push({"workspace_id":"bcc-policy-audit-nonexistent","prepare_only":true})`.
   Expect the same explicit locked denial.
4. `exec_run({"workspace_id":"agentporter","argv":["bcc-python","-B","-c","import sys,pytest; print(sys.version.split()[0], pytest.__version__)"],"timeout_seconds":30})`.
   Expect exit 0, Python 3.13.18 and pytest 9.1.1.
5. `qman_consult({"workspace_id":"qman","provider":"codex","profile":"jax","model":"gpt-6.1-terra","live":true,"allow_cached_fallback":false})`.
   Expect fresh live evidence or a precise refusal; never substitute cached data.
   Repeat for `provider:"copilot", profile:"phil"` if quota is needed.
6. Read `artifacts/bcc-chatgpt-audit-20261113/jax-scoped-tests.json` from workspace
   `agentporter`. It should show the private metadata inode, real object read,
   hidden host hooks/worktrees/home/socket, Python 3.13.18 and 88 passing checks.
   Reading this stored receipt verifies transport/readback, not a new job run.

Any new external model execution must first obtain fresh live quota, use a new
32-hex request ID and reconcile the exact job handle. Wei remains paused;
Argie/Agy remediation and Venkata/SciNet execution remain outside this repair.
