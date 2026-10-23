# AgentPorter implementation handoff to ChatGPT — 2026-10-21

**Later v17 installation review:** [the revised v17 install proposal](HANDOFF_AGENTPORTER_V17_INSTALL_REVIEW.md) supersedes this document's original v17 installation target with a process-tree cancellation revision. Neither revision is installed; use the exact new archive/hash and review gates in that proposal.

**Subsequent Cranary access task:** [the acquisition-only v18 report](cranary-acquisition-access-20261021.md) describes later changes, a separate v12-derived candidate and live GitHub acquisition. The mutable checkout has advanced beyond the v17 source pins below. Audit v17 from its frozen archive when reviewing this earlier checkpoint; do not confuse the acquisition-only v18 with deployment of the broader hardening.

**Checkpoint: source hardening implemented and tested; final v17 prepared for audit, not installation clearance. A7Dev remains working v12; A7 production is unchanged and has no active delegation relay. Do not declare rollout complete.**

Please independently audit the resulting implementation, exact artifact, and evidence. The implementing agent authored the new tests and automated archive cross-check; those are not an independent security signoff. No sub-agent has been represented as an independent reviewer of these changes.

## 1. Reconciliation and scope

Checkout: `/home/yeli/agent-work/agentporter-dev`, detached HEAD `65dbf445bcd16f8e6961a5d5eef4d9f76c084cf8`. Existing dirty/untracked work, v12/v13 artifacts, production preview v2, and root-private rollback evidence were preserved. No commit, push, root execution, privileged installation, service restart, production configuration write, account change, research-data edit, or training occurred during this handoff implementation.

Read all six requested documents. The closure addendum is service-owned `0600`; direct owner-user reads were denied. It was read through the existing authorized local MCP `read_file` interface instead of changing its permissions. Read-only copy: `/tmp/a7dev-closure-audit-owner-readable-copy.md`.

The audit's new ingress/resource/Headroom findings were real source gaps. The earlier v13 runtime also carried Wei's paid Go route and was not suitable for installation over the owner's repaired free default. Old v13 remains inactive. Intermediate v14–v16 artifacts are retained and superseded. The final source also closes scope-ledger connections deterministically, rejects ingress-policy YAML aliases, reclaims known capacity rejections, and keeps cancellation nonterminal until cleanup is verified.

| Requirement | Source implemented | Tests passed | Independently reviewed | Installed | Live verified |
|---|---|---|---|---|---|
| Cranary exact scoped HTTPS | Existing v12 | Yes | Existing review/evidence retained; no new signoff | Yes, v12 | Public/local MCP GitHub + CRAN and nine denials |
| Wei free default | Owner applied v12 route repair; strict broker now admits actual native free path | Yes; native v2.1.1 read | New strict-rule delta awaits review | Free route yes; strict broker no | v12 public default job yes; strict unprivileged compatibility yes |
| TLS origin/operation/body/Parallel controls | Retained and hardened | Full source gate + native checks | Prior reviews cover older source only; exact new artifact pending | No | New installed receiver/relay acceptance pending |
| Headroom half-close and deadlines | Yes | Synthetic streaming/half-close/stall/cancel + real Jax task | Pending | No | Unprivileged real canonical Headroom task passed |
| Public-client least privilege | Yes; separate principal/scopes/internal credential | Actual ASGI REST and MCP positive/negative tests | Pending | No | Existing public v12 still has broader permissions |
| Global admission, cancellation and worker budgets | Yes; durable max-three admission, pidfds, required cgroup envelopes | Synthetic negatives + native Bubblewrap lifecycle tests | Pending | No | Actual delegated cgroup CPU/memory enforcement not yet verified |
| Argie strict ACL compatibility | Investigated; endpoint remains denied | Existing native diagnostic fails closed | Semantics unresolved | No strict rollout | v12 success retained; strict Argie blocked |
| Production relay activation/rollback | Existing source preserved; stronger receiving admission guard added | Source/assembled/offline tests | New production/receiving artifacts not cleared | No | No new production live or rollback claim |

## 2. Implemented changes and affected files

- `src/agentporter/agents/development_egress.py`: bidirectional relay propagates write EOF with `SHUT_WR` and continues draining the other direction. Headroom removes the half-closed client from its read selector rather than abandoning the response. A second client request remains rejected. Provider idle bound is 300 seconds, absolute Headroom/opaque-relay bound 900 seconds; socket writes remain bounded and owning jobs retain runtime/output deadlines.
- `src/agentporter/agents/provider_egress.py`: Wei's strict admission is the **observed installed-client** `POST https://opencode.ai/inference/openai/v1/chat/completions`, with reviewed free-model IDs required in the body. Paid `/inference/go/...` paths are denied. The documented generic Zen URL was not assumed to be the native CLI path: two fail-closed probes identified the exact path before admission. Existing TLS authority/SNI/Host consistency, public-only address pinning, method/path restrictions, hosted-tool/MCP/opaque-state denials, encoded-body denials, and WebSocket rejection remain. Upstream response headers use the provider reasoning deadline instead of the short ingress header deadline.
- `src/agentporter/client_policy.py`, `middleware.py`, `server.py`: owner-installed `public-client-policy.yaml` pins workspace IDs to exact registry roots and explicit read/write/exec/HTTPS/Git/dispatch capabilities. General-key requests are public even from loopback. A different private internal key, on direct local transport, preserves authorized internal workflows. Forwarding headers do not turn a public key into an internal principal. Public job access requires durable public ownership. Public dispatch is read-only with no commit/push; unknown operations fail closed. Workspace inventory is filtered. The shared decorated functions enforce the same policy for REST and MCP. Scoped MCP uses stateless requests to avoid session principal retention. Required hardened startup refuses missing public policy or internal credential.
- `src/agentporter/admission.py`, `resources.py`, `resource_runner.py`, `process_handles.py`, `tools/jobs.py`, `sandbox/bubblewrap.py`, `tools/execution.py`, `scoped_https.py`: SQLite `BEGIN IMMEDIATE` admission covers async and direct execution across manager instances, max three jobs, no unbounded queue; REST capacity exhaustion is 429. Reservations remain held when cleanup/outcome is unverified. Raw/scoped launch failure paths are centralized. Cancellation uses kernel pidfd handles, not stored numeric PIDs/PGIDs; libc wrappers support the portable Python build lacking `os.pidfd_open`. Cgroup v2 envelopes set 4 GiB memory, no swap, 128 processes, and two CPU equivalents per worker, before exec. Gateway startup requires an owner-delegated supervisor layout, takes an exclusive recovery lock, drains recognized old envelopes, and does not signal persisted PIDs. Unknown/populated/untrusted cleanup fails closed. Generic synchronous execution and the fixed HTTPS worker use envelopes too.
- `src/agentporter/workspaces/bounded.py`, `tools/files.py`, `tools/artifacts.py`: descriptor-based, nonblocking regular-file reads reject hardlink aliases and enforce byte size before hashing. Full reads cap at 1 MiB; ranged reads/hash work cap at 8 MiB and selected output at 1 MiB. Large/sparse files, FIFO/alias reads, long-line output and excessive traversal fail with explicit bounds. Traversal is lazy, excludes directory symlinks, limits 5,000 visited entries and depth 16. Search capture has time/output bounds. Existing-file write hashing is bounded. Text artifacts over their budget are rejected rather than scanning an arbitrarily large file.
- `src/agentporter/agents/development.py`: production receiving admission now requires public-client isolation and configured resource envelopes as well as strict provider egress and explicit admitted agents.
- Final recovery integration: known pre-launch `JobCapacityError` rejections mark receiving relay reservations spent but inactive, retaining idempotency without leaking capacity. Verified recovery produces terminal `interrupted` jobs with stable duration; relay reconciliation recognizes that state. Cancellation remains `cancelling`, with no exit/finished metadata, until the monitor verifies cleanup. Cleanup failure is recorded as `cleanup_failed` and keeps capacity, including for cancelled jobs. The full gate caught the original early-terminal cancellation race; delayed-cleanup, failure-injection and five-rejection assembled-ASGI regressions now cover it.
- New tests: `tests/security/test_closeout_lifecycle.py`, `test_closeout_file_bounds.py`, `test_closeout_client_policy.py`, `test_closeout_resources.py`. Existing integration fixtures were updated to use real admission bookkeeping; public Obsidian fixtures now declare public modes explicitly, independent of test umask. Runtime tests reject production admission without ingress/resource settings.
- New preparation/audit tools: `scripts/prepare-closeout-candidate.py`, `prepare-closeout-harness.py`, `audit-closeout-artifact.py`, `canonicalize-closeout-artifact.py`. `verify-provider-origin-sandbox.py` now tests Wei's free route without paid credentials and records redacted static path decisions. The final builder packs canonical tar/gzip metadata directly; synthetic timestamp changes produce byte-identical archives.
- Proposed inert owner configuration: `docs/examples/a7dev-public-client-policy.yaml`, `a7dev-job-resources.conf`. The candidate embeds both under `operator-plan/`; neither was installed. The proposed public scope permits Cranary read/HTTPS/read-only dispatch and AgentPorter-dev read/read-only dispatch. It grants no generic writes, shell execution or Git mutations, and excludes Obsidian and unrelated projects. Owner must approve the exact scope.

## 3. Installed releases and frozen candidate

**Actual A7Dev:** release `20261021T132836.936455Z`, PID `4102155`, active, no restart. Public/local MCP loaded and disk fingerprint both `04a978d2746a88afe79c56af673e6d19850ef24aca9b382becc14426fa8a4fcd`, `stale=false`. Wei's separately applied free route and Cranary private policy persist outside the immutable release.

**Actual A7:** current release directory `/home/yeli/.local/share/agentporter/releases/65dbf445bcd16f8e6961a5d5eef4d9f76c084cf8`, PID `664960`, active, unchanged. Its installed on-disk package fingerprint is `8de423283d3db8938a226719650a6c3b8fb325c534154992636bb6c51bf490a8`. This was computed using that release's interpreter, without opening production credentials. The live process's authenticated `loaded_fingerprint` was **not queried** in this pass; ChatGPT/owner should query it through the existing A7 connection. Production `delegation-upstream.yaml` and `delegation-relay.key` are absent by file-presence checks.

**Final v17 candidate:** version `20261021T181600.679372Z`, package fingerprint **`085b63bf291595817d81ae99a14967e10b7a9d56138f39ddbd5ca27b273dbf2d`**, 26,353 manifest entries and 73 package source files. Frozen canonical archive `/tmp/agentporter-development-candidate-v17.tgz`, SHA256 **`acbc64e95e238a3d568035834b75949456064445af89110bc68ddf8d18c6c72f`**. Build report `/tmp/agentporter-development-candidate-v17-review.json`; source pins `/tmp/agentporter-closeout-source-v17-manifest-20261021.json`; build log `/tmp/agentporter-closeout-v17-build-20261021.log`.

The identical read-only review copy is [review-artifacts/agentporter-v17.tgz](../review-artifacts/agentporter-v17.tgz), mode `0444`, a separate inode from the private original. Sanitized, hash-indexed receipts are in [evidence/agentporter-closeout-v17-20261021](evidence/agentporter-closeout-v17-20261021/sha256.json). These project-local files are readable through the existing authorized A7Dev workspace interface; raw private native transcripts and credentials are not exported. Older v15 review files remain present but are superseded.

For a connector-side archive audit, use the existing authorized `agentporter-dev` offline execution interface to run `python3 -I scripts/audit-closeout-artifact.py` against `review-artifacts/agentporter-v17.tgz`, with the exact SHA above, `--source-manifest docs/evidence/agentporter-closeout-v17-20261021/source-manifest.json`, and a report under sandbox `/tmp`. The helper prints the bounded result. Use a job with sufficient timeout and inspect its exit/output. This needs no network, owner key, service restart or installation. Review the helper itself before trusting its output.

Retained superseded v14: `/tmp/agentporter-development-candidate-v14.tgz` SHA256 `873129115f5768d526f57dbf194270426a07184a2879fe8429443c356b5d06b4`, canonical encoding `/tmp/agentporter-development-candidate-v14-canonical.tgz` SHA256 `93c2c443a4e9371986a58fd24809112f34926ad59215b0b6dd58e70caad1681f`. Its full extracted-harness gate and separate streaming archive audit passed, but it is not the final review target. The retained v15 archive has SHA256 `adffc6dd87e5103340ae85517b1e3235be5fdc659dcb4ad5694fe0f6fcc6eb51`; v16 has SHA256 `54933c5e833783b8050ef1101d0a1764e13f3a9bd286a66ccb5d3ccfeee1d00c`. Neither is the final review target. Final source includes the subsequently reproduced relay-capacity and cancellation-order repairs.

The reviewed v12 base hash remains `e35b83635f96feb97b533709bbad1c7b5c4054bf6f9c8bcc7d51af8dacd664a5`. Existing shared resource admission digest is preserved. New runtime uses strict egress, mandatory ingress policy/resources, Wei's free profile and existing non-secret `free-access` file, and a conservative **production admission proposal of Liz/Prof only**. Ming later recovered after the reported reset and passed the exact frozen-client check; that recovery does not automatically expand the proposed two-agent production grant. This runtime is not active.

Canonical archive audit and extracted-payload gate results are recorded in the final checkpoint receipt below. The canonical encoding normalizes gzip/tar timestamps/ownership; synthetic equal-payload/different-metadata inputs produced byte-identical output. No payload bytes or version were changed by normalization.

## 4. Exact verification commands and evidence

**Executed locally, final source:**

```bash
bash scripts/verify-development-candidate.sh > /tmp/agentporter-closeout-source-final-v17-20261021.log 2>&1
```

Result: **1,439 pytest passed, 24 subtests passed, all standalone verifiers passed**. One existing Starlette/AnyIO deprecation warning remains. Earlier runs exposed and corrected an ASGI test context omission and synthetic fixture modes under private umask; portable Python's absent pidfd wrappers were handled through libc. Those earlier failed runs are preserved as `/tmp/agentporter-closeout-source-gate*-20261021.log`; they are not presented as final passes.

```bash
.venv/bin/python scripts/prepare-closeout-candidate.py --source-manifest /tmp/agentporter-closeout-source-v17-manifest-20261021.json --version 20261021T181600.679372Z --output /tmp/agentporter-development-candidate-v17.tgz --report /tmp/agentporter-development-candidate-v17-review.json --extract-to /tmp/agentporter-development-candidate-v17-extracted
```

Build verified the pinned base, exact manifest, changed files, full round-trip extraction and metadata identity. It did not execute, install or activate the payload.

**Artifact code acceptance:** `/tmp/agentporter-closeout-v17-harness-20261021` uses the extracted candidate's actual interpreter, dependencies and non-editable source. Only `venv/pyvenv.cfg` and the package `.pth` are relocated to the private extraction directory; hashes are recorded in `/tmp/agentporter-closeout-v17-harness-20261021.json`. Tests/scripts and three required checked-in policy/schema documents are a copied harness, not additional installed runtime payload. Commands:

```bash
.venv/bin/python scripts/prepare-closeout-harness.py --extracted /tmp/agentporter-development-candidate-v17-extracted --harness /tmp/agentporter-closeout-v17-harness-20261021 --report /tmp/agentporter-closeout-v17-harness-20261021.json
cd /tmp/agentporter-closeout-v17-harness-20261021
PYTEST_ADDOPTS='-o pythonpath=/tmp/agentporter-development-candidate-v17-extracted/release/src' bash scripts/verify-development-candidate.sh > /tmp/agentporter-closeout-v17-artifact-gate-20261021.log 2>&1
```

Result: **1,439 pytest passed, 24 subtests passed, all standalone verifiers passed**, exit 0; pytest took 91.46 seconds and emitted one existing deprecation warning. This is extracted-artifact acceptance, **not installation, service-UID admission, or live resource enforcement**. An isolated import with that interpreter confirmed the exact package fingerprint and source path. Full post-test payload verification permits only the two recorded path relocations; all other 26,353 manifest entries and 73 current source pins are checked again.

Separate streaming archive cross-check (stdlib only, no extraction or payload execution):

```bash
/usr/bin/python3 -I scripts/audit-closeout-artifact.py --artifact /tmp/agentporter-development-candidate-v17.tgz --sha256 acbc64e95e238a3d568035834b75949456064445af89110bc68ddf8d18c6c72f --source-manifest /tmp/agentporter-closeout-source-v17-manifest-20261021.json --report /tmp/agentporter-closeout-v17-streaming-audit-20261021.json
```

Result: PASS, 26,353 exact payload entries, 3,458,326,979 expanded bytes, 73 exact source files and expected fingerprint. Duplicate, traversal, special/hardlinked/sparse entries and escaping or looping symlinks are rejected. Report and post-test receipt are copied into the final evidence directory. This cross-check was written by the implementer and does not satisfy independent review.

**Live preservation check:** `.venv/bin/python scripts/verify-a7dev-cranary-https.py --after` passed again against actual public/local v12. Log `/tmp/agentporter-closeout-live-cranary-20261021.log`; evidence `/tmp/a7dev-cranary-https-verification-91d22l0t/results.json`. GitHub HEAD/GET and CRAN HEAD succeeded, all nine network denial cases and offline workspace isolation passed. Unauthorized Location handling remains synthetic; live `-L` is denied. No unrestricted egress was enabled on the installed service.

`git diff --check` passed. Final inventory and tracked diff: `/tmp/agentporter-closeout-final-worktree-status-20261021.txt`, `/tmp/agentporter-closeout-final-tracked-diff-20261021.patch`; earlier receipts are preserved. The inventory includes inherited changes and must not be treated as permission to commit them all. Final read-only status checks confirmed system A7Dev PID `4102155`, active, zero restarts, and **user** `agentporter.service` PID `664960`, active, zero restarts. The similarly named system unit is inactive and is not production. The final evidence index also pins all 114 harness test/script files, records the five agents' sanitized native tool events, and includes source/artifact logs, release/CLI provenance, relocations, post-test payload checks and final service state.

## 5. Real provider-backed evidence by agent

Commands use `.venv/bin/python scripts/verify-provider-origin-sandbox.py --agent NAME --execute-provider-call`. Native diagnostics intentionally retain `verified:false` until someone separately inspects actual events. Parent inspection receipt: `/tmp/agentporter-closeout-native-parent-review-20261021.json`.

| Agent | Fresh strict-broker result | Evidence and limits |
|---|---|---|
| Jax | PASS, real native local-tool read, exact undisclosed nonce, 10.17 s | `/tmp/provider-origin-jax-result-czt43g3i`; canonical Headroom retained, no provider/model substitution. No new optimization attribution claim. |
| Liz | PASS, completed native command read, exact nonce, 13.77 s | `/tmp/provider-origin-liz-result-tpv9s7cr` |
| Prof | PASS, completed native command read, exact nonce, 13.28 s | `/tmp/provider-origin-prof-result-ngnlygr1` |
| Wei | PASS, completed native `read`, exact nonce, 8.28 s | `/tmp/provider-origin-wei-result-9avx_5zr`; exact installed v2.1.1 CLI, anonymous public placeholder, `glm-5.3-flash-free`; admitted actual native endpoint. Earlier two denied-path probes retained. |
| Ming | PASS after reported reset, including exact frozen CLI; completed native `Read`, exact nonce, 6.29 s | `/tmp/provider-origin-ming-result-62psq2kn`. Earlier session-limit failure `/tmp/provider-origin-ming-result-wwzuri8m` is retained. One check after 17:50 UTC recovered, followed by the exact frozen-client check. Optional telemetry/bootstrap paths stayed denied; no account/model change or quota bypass. |
| Argie | BLOCKED under strict egress; existing v12 success retained | Existing strict diagnostic `/tmp/argie-native-policy-result-be2xc_8p/summary.json` exits 3 at denied ACL RPC. Installed v12 real skill/file task is recorded in `docs/a7dev-v12-live-acceptance-20261021.md`. |
| Phil | DEFERRED, quota; not tested or changed | Do not claim provider verification. |

These fresh diagnostics are unprivileged synthetic-workspace client compatibility checks, not installed service-UID tests. Canonical account profiles are handled by the existing launcher; credential file contents were not inspected or printed. Shared skills/38-tool admission and earlier v12 skill/file acceptance remain separate evidence. New exact-artifact service-UID skill/tool/network acceptance for each available agent is still required after authorized installation.

CLI provenance was checked separately: tested Jax/Liz/Prof executables and bundled Codex helpers match the frozen payload bytes; Wei's tested installed v2.1.1 executable matches too. Ming's interactive binary was newer, so the successful exact-frozen-client test above used `--artifact-cli-root /tmp/agentporter-development-candidate-v15-extracted/release/cli`. CLI payloads are unchanged from the pinned v12 base in later candidates. Provenance receipt: `/tmp/agentporter-closeout-cli-provenance-20261021.json`.

Wei's earlier actual public v12 job `job_d067ca9669534b88ad51024c` completed read-only with no model override and matching README SHA256; evidence `/tmp/a7dev-wei-free-public-hjb5uxs9/`. Configured route is known; public `actual_model` metadata is unknown and must not be fabricated.

## 6. Argie decision and remaining security risks

Observed blocked request: `POST /v1internal:writeTrajectoryAcls`, shape `{trajectoryId: string}`. Prior bootstrap requests reach canonical service authorities before this RPC; rejecting it aborts native startup before a model turn. This establishes a normal-start dependency for that client path, **not proof that the ACL write is essential to authentication**.

Native `agy --help` exposes no supported switch specifically disabling this ACL step. Static binary names confirm the RPC label but do not establish default principals, permissions, visibility, propagation or retention. No authoritative public request/response contract was found in the targeted search. A third-party proxy returning an empty success response is not evidence of safe upstream semantics and was not adopted.

**Decision: keep the ACL-writing endpoint denied.** Do not send it upstream for an experiment, forge a success response, silently substitute a provider, or treat a trajectory ID as proof of owner-only effects. Require authoritative semantics or a supported native no-ACL mode before lifting the strict Argie hold. Installing this strict candidate now would regress working v12 Argie; this blocks calling the full seven-agent development rollout accepted.

Other pending security evidence:

- Actual live public ingress still uses v12's broader authenticated tool registry. New scopes are source/artifact only. This is a compromised authenticated key's blast-radius issue, not an established unauthenticated bypass.
- Active A7Dev currently has `Delegate=no`, `MemoryMax=infinity`; controller files are root-owned and not delegated. The proposed cgroup path must be independently reviewed, owner-installed, and verified under actual service UID. Synthetic control-file tests and fail-closed refusal do not prove kernel memory/CPU limits are active.
- Exact v17 source, custom TLS trust/broker body rules, public-principal propagation, pidfd lifecycle, cleanup/recovery, cgroup setup and operator scope need independent review. Previous reports do not automatically cover new hashes or undocumented future provider capabilities.
- New installed payload verification, interrupted-install/rollback exercise, old-key/internal-key separation checks, streaming/cancellation under actual resource limits, and per-agent skill/tool acceptance are pending.
- A7's authenticated loaded fingerprint is not freshly verified; only installed disk fingerprint and unchanged PID/release were checked without reading its credential.

## 7. Production relay status and Phase D dependency

No production relay credentials, scopes, release, listener or activation were created. Production remains authoritative for unrelated tools. Existing reconciled source preview `/tmp/agentporter-production-candidate-source-v2` is preserved, but it predates this hardening and is **not** a production candidate for these changes.

Phase D remains parked behind development review/installed acceptance. After those gates pass, reconcile the current A7 package (including Parallel Search) into new immutable production and receiving artifacts, obtain independent review, and present exact owner-approved scope/credential/setup changes. Initial production admission may use Liz/Prof only as proposed; revalidate availability immediately before activation. Dedicated relay credentials must differ from public/internal API keys. No unconfined worker fallback is permitted.

Then verify positive delegation plus wrong keys/routes/workspaces/roots/agents, write/commit/push/cancel denial, job ownership, quota/uncertain outcomes, restart recovery and exact rollback without affecting unrelated production tools. No such new production live acceptance is claimed here.

## 8. Rollback and recovery

No live deployment occurred in this implementation phase, so no new rollback is necessary or claimed as demonstrated live.

Preserved live v12: `/opt/agentporter-development/versions/20261021T132836.936455Z`; its earlier root-private rollback evidence `.candidate-32a8c77e2ae39572aa57f417d0b40960` still exists. **That older receipt rolls back the historical v12 installation; it is not a v17-to-current-v12 receipt.** Do not run it to undo this work.

Before any future installation, the reviewed owner launcher must snapshot the **current** v12 release/runtime pair, which now includes Wei's free configuration, plus existing Cranary `public-https.yaml` and the presence/absence/content/modes of proposed ingress/internal-key/systemd-drop-in controls. The old v12 archive's `runtime.json` still contains the obsolete Go profile: blindly restoring that historical runtime would regress Wei. Preserve the current owner-applied runtime and scope, not merely the old archive.

The existing immutable installer supports paired release/runtime evidence and rejects a mismatched active candidate; synthetic exact-pair/unsafe/interrupted-install tests are included in the full gate. A reviewed future launcher must extend rollback to new owner-installed control files/drop-in state, stop only A7Dev, restore that exact pair and control state, restart only A7Dev, and verify public fingerprints plus Wei/Cranary acceptance. Restoring v12 also restores its known broader ingress/worker-egress capability; do not describe it as hardened v17.

For resource recovery, required hardened startup takes an exclusive supervisor lock, requires exclusive supervisor membership and no unknown child groups, kills only recognized `apj_<uuid>` cgroups and waits for `populated=0` before releasing durable capacity. Unknown cleanup stays held; do not clear SQL reservations or signal stored PIDs merely to free slots.

## 9. Uncommitted work

All work is uncommitted on the inherited detached checkout. The new source modules, scripts, tests, examples and this handoff are mixed with earlier session-owned/unrelated dirty and untracked files. The exact inventory/patch receipts above distinguish the current tree from HEAD, not authorship. No commits/pushes were requested or performed. Preserve old candidates, test evidence and protected rollback receipts.

## 10. Questions requiring independent review / owner approval

1. **ChatGPT independent audit:** inspect exact v17 hashes, manifest deltas, actual native events, REST/MCP scope tests, TLS/body/Parallel restrictions, Headroom lifecycle, pidfd/cgroup cleanup and failure cases. Are there remaining bypasses or regressions? Re-run checks independently; do not accept implementer-authored tests as automatic security clearance.
2. **Owner scope/resource approval after review:** approve or revise the inert two-workspace public scope and separate internal credential; approve exact A7Dev-only `Delegate=cpu memory pids`, `DelegateSubgroup=supervisor`, 16-GiB aggregate/no-swap, 600%-CPU and 512-task drop-in plus per-worker envelopes. No protected write/restart/installation is authorized by this document itself.
3. **Argie protocol decision:** obtain authoritative ACL semantics or a supported client mode avoiding this RPC. Until then, keep strict Argie and full-seven-agent rollout on hold; preserve working v12.
4. **Final acceptance/production:** after exact reviewed owner installation and installed service-UID acceptance, decide the dedicated production relay workspace scope, credential installation, receiving/production artifacts, and controlled rollback test. Separately obtain A7's authenticated loaded fingerprint through its existing connector. Phil remains deferred; revalidate the admitted identities immediately before any future production activation.

### Final checkpoint receipt

Source **implemented** → source and frozen-artifact tests **passed** → exact artifact **not independently reviewed** → **not installed** → new installed controls **not live verified**.

Final review target is v17 only, SHA256 `acbc64e95e238a3d568035834b75949456064445af89110bc68ddf8d18c6c72f`. Both complete gates passed 1,439 tests/24 subtests and every standalone verifier. Streaming archive and post-test manifest checks passed. Fresh native tool execution passed for Jax, Liz, Prof, Ming and Wei; Argie remains blocked and Phil deferred. A7Dev v12 and production are preserved.

The next owner action, **after independent review**, is approval of a concrete installer/rollback plan covering `/var/lib/agentporter-dev/config/public-client-policy.yaml` (service owner, `0600`, example SHA256 `c96097f5ecac13a4186fe2b0e8f0294a33cab054c9f4dde7439decec261e3210`), a distinct private `/var/lib/agentporter-dev/config/internal-client.key`, and an A7Dev-only systemd drop-in (proposed `/etc/systemd/system/agentporter-development.service.d/job-resources.conf`, example SHA256 `5d934b1780a461b653cae680a7f525b9affe646c8b1006ecafe4df5ddecdbb5c`). The launcher must first snapshot the current Wei-free/Cranary configuration and all affected control state. No privileged activation command is cleared here; do not install this strict candidate while treating the known Argie regression as resolved.

**ChatGPT: independently audit this implementation and its evidence, report any bypasses/regressions, and identify which gates are actually cleared before proposing installation or production activation.**
