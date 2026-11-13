# BCC AgentPorter consolidation repair — 2026-11-12 handoff

Completed verification on 2026-11-13. Terminal/system commands, AgentPorter,
and both Qman entrypoints now use one selected installation of each agent CLI.
Native accounts remain separate. Five active agents completed real B6 responses,
and a delegated edit persisted in the canonical repository. B6 commits and
pushes remain LOCKED under Lennon's selected owner-run Git workflow.

## Scope and provenance

Prof continued Ming's Claude session
`16f8dd3a-32cb-47f1-8cd5-1a0e4e4487c5` in the current Codex university-research
account. The source transcript was read in place. The requirements came from
`BCC_AGENTPORTER_CONSOLIDATION_2026-11-12.md` in shared memory. Repair activation did not switch accounts, copy the transcript, or publish Git
changes. Lennon subsequently requested publication of the isolated repair to the
`bcc` branch. Existing Nida, Qman-refresh and other foreign source changes remain
outside this repair commit and are preserved in the original checkout.

Lennon explicitly approved activation on November 13 and selected one shared
copy of each agent CLI, while retaining separate AgentPorter gateway/worker
application packages. He replaced browser signing with chat approval followed
by owner-run Git. Asgard/A7 work, Argie/Agy remediation and Wei model dispatch
were excluded; CLI installation checks did not run Wei or Argie model work.

## Findings corrected

- Worker Codex auth snapshots were expired while the three native accounts had
  current authentication. Rotating copied refresh credentials in disposable
  homes was unsafe. Native canonical stores now remain authoritative.
- Ming's worker referenced an expired Claude credential snapshot. It now obtains
  current native access without a refresh token. Phil's worker now reads fresh,
  filtered native account authentication instead of a provisioned durable copy.
- CLI copies diverged among NVM, system commands, native managed daemons,
  embedded worker releases and Qman's pinned runtimes. The old updater also
  rewrote CLI files inside sealed historical releases, invalidating their seals.
- Writable v14 jobs could receive automatic commit authority. Git action policy
  and the publication boundary now independently deny unapproved history/ref
  changes, including raw writes and commits after an approved pull.
- B6 live Qman selectors/schema were inconsistent. Exact scope and explicit
  `allow_cached_fallback:false` now produce live evidence or a precise refusal.
- The current Copilot CLI needs read-only policy/feature bootstrap requests.
  The broker now admits exactly `GET /copilot_internal/managed_settings` at
  `api.github.com` and `GET /meta` at its existing Copilot API origins. Native
  diagnostics observed these requests. GitHub's [managed-settings documentation](https://docs.github.com/en/copilot/reference/enterprise-administrators/enterprise-managed-settings)
  describes the startup policy mechanism. Repository APIs, token issuance,
  team customization and hosted MCP routes remain blocked.
- Copilot 1.0.111 sends Zstandard-compressed JSON. The broker now accepts one
  complete regular zstd frame only for admitted Copilot model POSTs with JSON
  content type, bounds compressed and decoded bytes to the existing 16 MiB
  limit, rejects suffixes/multiple frames, and validates decoded JSON before any
  upstream connection. It forwards identity framing and exactly those inspected
  bytes. Other providers and the Headroom validator retain their encoding rules.
- Stable `current/bin/<provider>` links prevent vendor npm placeholder/layout
  changes from selecting a non-executable launcher.
- The obsolete missing `bcc-production-canary` workspace was unregistered.

## Active installation and custody

Shared code: `/opt/agent-clis/current`, currently selecting
`/opt/agent-clis/releases/20261113T164211Z-fde40fb9`.

| CLI | Version |
| --- | --- |
| Codex | 0.169.0 |
| Claude Code | 2.1.323 |
| GitHub Copilot | 1.0.111 |
| OpenCode | 1.19.5 |
| Agy | 1.5.8 |

Local, NVM, system and OpenCode legacy command entrypoints select the shared
launchers. The system Copilot editor shim no longer takes precedence over them.
Jax/Liz/Prof managed package selectors and their running native daemon
executables resolve to the same Codex inode. Idle Jax/Liz daemons were aligned;
the active Prof daemon's executable/helper/resource inodes were preserved.
Native auth, settings, sessions and histories were not merged or moved.

`agentporter-bcc-{gateway,worker}.service` and the credential broker use sealed
`consolidation-20261113-10-{gateway,worker}` application packages, with no embedded
`cli/` tree. The Qman service uses that gateway package. The terminal Qman
launcher uses `bcc-qman-shared-cli-20261113-01`: its original command/store code
was retained, and only two collectors plus their shared-code helper changed.
Its old/new `--help` output is identical; installation and direct live collector
checks did not open/change the Qman database.

The owner credential broker runs as yeli, verifies the actual worker UID over a
private UNIX socket, checks enrolled account bindings, and emits redacted audit
labels. Codex workers get bounded access with an empty refresh token; renewal is
requested from the intended native daemon. Claude gets bounded access without
refresh authority. Copilot gets only intended-account authentication fields.
Workers never write auth back to native stores. Account change, unavailable
native authority or insufficient lifetime fails closed with no account fallback.
The credential socket is not mounted into worker namespaces.

Three Codex accounts remain distinct. Claude binding uses its native account
configuration; Copilot retains its native login/host guard. This does not add
provider-verification claims to Qman's separate identity/entitlement fields.

## One update authority

`updateCLI --status` shows the current selection; `updateCLI` performs an
administrator-authorized shared update. Root-owned controller sources are in
`scripts/bcc-shared-cli.py` and `scripts/bcc-shared-cli-update-runner.py`.
`deploy/bcc-shared-cli/` contains the installed unit sources.

`bcc-shared-cli-update.timer` replaces the existing 02:00 user updater cron
entry, maintaining one daily update path. The protected service successfully
staged and promoted all five CLIs. It executes downloads/version checks as yeli
with an empty staging HOME and inaccessible native credential directories;
package lifecycle scripts do not run as root. Root verifies the staged manifest,
imports only code, strips special modes, deduplicates equal code inodes and
atomically selects the release. Successful staging copies are retired. No
permanent sudo permission was added. Native/provider automatic selectors are
disabled through their settings/launch environment.

Historical application/code releases and exact preimages are retained for
recovery. They are not selected installations. The tracked Obsidian updater was
not edited; its installed command link and old scheduled invocation were replaced.

## Verification

All paths below are relative to `artifacts/bcc-consolidation-20261112/`.

| Acceptance | Evidence | Verification |
| --- | --- | --- |
| Selected binary hashes, all seven worker mappings, system aliases, native daemon inodes, service seals/PIDs, locked Git policy, existing workspaces, one timer | `shared-installation-20261113.json` | Executed locally |
| Current B6 source/disk parity, generated 31-operation schema, commit/push denial, canonical offline edit/readback, hidden native auth/socket/host-temp sentinel, live no-cache Qman and exact errors | `live-acceptance.json`, `active-openapi.json` | Executed locally through authenticated B6 REST |
| Actual Jax, Liz, Prof, Ming and Phil responses | `final-agent-checks-20261113.json` points to each passing job receipt | Executed locally through B6 |
| Actual delegated Liz edit with exact canonical content and terminal cleanup | `shared-cli-delegated-write-final-20261113.json` | Executed locally through B6 |
| Six concurrent actual-UID credential issuances across three Codex accounts; native login acceptance; no refresh/writeback | `credential-custody-final-20261113.json` | Executed locally |
| Ming/Phil actual-UID native credential issuance and Claude access-only auth status | `credential-custody-final-20261113.json` | Executed locally |
| Native Qman reads fresh Codex and Copilot quota using shared binaries, without DB/model work | `native-qman-shared-cli-check-20261113.json` | Executed locally |
| Actual external ChatGPT workspace discovery and live Jax quota | `external-chatgpt-receipt-20261113.json` | Owner-reported external execution |
| Guarded old/new application/configuration restoration and replay, sealed-source/PID checks, discovery timer restoration | Root generation 10 controller journal | Executed locally |

The external receipt was collected at 10:21 EST, before CLI consolidation, and
reported Codex app-server 0.163.0. Subsequent local B6 and terminal checks verify
0.169.0. The external connection/authentication origin and published operations
were retained; no second external call at 0.169.0 is claimed.

The final machine receipt observed 38 configured workspaces, all present. Registry
counts can change as the existing discovery timer reconciles workspaces.

Relevant automated verification:

- Consolidation baseline: 363 source tests passed / 120 installed worker tests
  passed / 126 installed gateway tests passed; one expected source/worker skip.
- Shared CLI/runtime and credential checks: 166 passed, one skipped.
- Extended provider custody/runtime checks: 156 passed, one skipped; 32 tests
  passed against each frozen installed-name gateway/worker candidate.
- Provider metadata/zstd/security checks: 152 passed in source and 152 against
  the frozen installed-name candidate; gateway/worker deltas were identical.
  These include real local TLS forwarding, unknown-size zstd, decoded-size
  bombs, truncation, concatenated frames, suffix bytes and hosted-tool denial.
- `git diff --check` and script compilation/shell checks pass.

Publication validation on the isolated `bcc` branch also passed 961 focused
source/unit/BCC checks (eight skips for optional installed-only capabilities)
and 20 relay/native-worker policy checks. Those tests use synthetic credentials
and no provider model calls. The source snapshot excludes unrelated Nida and
Qman-refresh work; its public action catalog retains the existing 35 actions.
Push CI is enabled for the `bcc` branch.

The full native repository suite is **not green**: older recovery and
repository-birth fixtures still assume that a worker may publish Git history
without separate authority. An expanded run exposed those conflicts and was
stopped; the focused passing counts above are not a full-suite pass. Unit,
relay and named-worker assertions were updated to verify separate edit/commit
authority, including rejection before reservation and unchanged canonical
history after a raw worker commit. Remaining low-level recovery fixtures were
not rewritten as part of this publication request.

Initial checks exposed an old system Bubblewrap binary, a test fixture's file
mode, a setup portability error, npm launcher placeholders, a Copilot automatic
model/reasoning mismatch, capacity rejection and overly frequent status polling.
Those failures are retained as historical evidence. Correct native sandbox
selection, stable links, default-model requests, sequential admission and bounded
429 backoff were applied. Rejected/not-launched jobs were not treated as model
successes or repeated as uncertain executions. Existing upstream deprecation
warnings and intentional egress refusals do not authorize broader operations.

## Current operating limits and recovery

Live quota owner policy still admits `codex/jax` and `copilot/phil`. Liz/Prof
return a precise authorization refusal; Claude has no invented live collector.
Qman preserves persistent-binding, entitlement, native-client verification and
reset-counter limitations. Actual responses prove those specific executions.
Wei/Argie model work and Venkata/SCINET/Asgard operations were not dispatched.

Lennon's selected Git workflow is in `docs/CHATGPT_B6_OPERATIONS.md`. B6 commits
and pushes stay locked; approval in chat does not create a server signing receipt.
Source changes remain uncommitted for owner review.

Latest application recovery control:
`/var/lib/agentporter-bcc/consolidation-20261113-10/rollout.py --rollback`, run
with the installed isolated Python and machine administrator access. It holds
existing production/discovery locks, refuses active jobs/concurrent owner edits,
blocks admissions, restores exact prior control files, verifies source/PID parity
and restores discovery. It accepts both pending and accepted active state.
The prior application predates the Copilot transport fix; account for that older
behavior during recovery. Shared CLI selection and native Qman binding have
separate recorded preimages. Earlier generation controllers are historical and
must not be replayed against the current state without first restoring their
expected predecessor. Current acceptance is recorded in the root-owned generation 10 `ACCEPTANCE.json`
and `/var/lib/agentporter-bcc/consolidation-current.json`; active phase is `accepted`.

The temporary BCC sudo rule has intrinsic expiry 2026-11-13 18:55:48 UTC.
The scheduled shared updater does not depend on that grant.
