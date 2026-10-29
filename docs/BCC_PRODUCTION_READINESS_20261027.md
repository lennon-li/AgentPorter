# BCC production readiness — 2026-10-27

**Decision: HOLD. Full rollout with confined agents is the requested target.**
Production activation has not been performed. The existing BCC gateway and
tunnel remain running. Passing source tests is not production clearance.

## Current source candidate — Liz continuation

Candidate: `/tmp/agentporter-bcc-production-XCkSZH`. Final native source gate:
**2,447 passed, 21 skipped, 24 subtests passed**, one existing upstream warning,
in 97.88 seconds. Internal scoped smart-HTTP primitives now interoperate with
native Git for SHA1/SHA256 push/fetch and preserve concurrent remote changes;
Internal signed push now binds exact state and packs to owner receipts, with
durable admission and owner reconciliation. Network Git is still publicly
locked pending owner-device signing and authenticated API integration.
The independent owner-device approval interface now signs
real disposable-repository commits in an isolated browser test; independent
hosting and real device enrollment are not yet performed. The two formerly retained legacy history-bypass failures are
fixed. Generic canonical writable binds are removed; writable production jobs
retain the supervised private-overlay path. Additional native regressions
fixed trusted checkout reflog aliases, worktree redirection, and read-only
delegated-agent secret aliases. This is a source gate, not a live acceptance
PASS. No source from this continuation has been installed in running services.

Current activation blockers include the owner-run cross-owner overlay probe,
independent issuer provisioning, public signed network Git integration, installed
profile/resource/provider verification, immutable rollout, and independent
AP-01 through AP-06 acceptance. Read the latest sections at the end of this
file for source changes, exact evidence, artifacts, and remaining work.

## Earlier update — owner prerequisites installed; isolated staging prepared

The earlier snapshot below is historical. The owner installed the verified
Bubblewrap at `/opt/agentporter-bcc/bin/bwrap` and created the private worker
account UID/GID 997. Native verification confirmed both prerequisites.

The candidate now supports only two explicit root-controlled sandbox paths,
including BCC's installed path; it rejects arbitrary, symlinked, writable or
setuid replacements. A non-root supervisor bootstrap supports systemd 249 by
moving only its own process into the delegated subgroup and verifying the
kernel membership. It does not create delegation or grant itself privileges.
Jax's screened BCC profile uses Headroom on port 8787; that exact host-local
model capability is now supported alongside Asgard's 9787, with matching Host
validation and no arbitrary loopback port selection.

Latest native source gate: **2101 passed, 21 skipped, 24 subtests passed**;
one upstream Starlette/AnyIO deprecation warning. The skipped cases comprise
19 missing frozen Cranary/SciNet fixtures and two installed-provider smoke
cases that require the owner-run staging environment. They are not live
acceptance passes. All 34 hostile installer/sandbox/supervisor checks pass.
The updated wheel's synthetic HTTP/sandbox smoke passed. Static systemd-249
unit validation passed with only its not-yet-installed executable path
substituted for validation; actual startup remains to be verified.

Staging capsule and operator helper:

- Local directory: `artifacts/bcc-stage-20261027-03/` (private and ignored).
- Immutable release archive SHA256:
  `fcb50cb0812a92d756418180ad2a72931669660647d1092659d5ce6d9369b427`.
- Owner-installed helper SHA256:
  `b28328682772415c9f001c1f3a44adff218241d35f872a9032919eaaf44de334`.
- Intended trusted helper location:
  `/usr/local/libexec/agentporter-bcc-stage-install.py`.
- Intended release:
  `/opt/agentporter-bcc/releases/bcc-stage-20261027-03`.
- Intended private staging data:
  `/var/lib/agentporter-bcc-worker/staging/bcc-stage-20261027-03`.
- Intended system service: `agentporter-bcc-worker.service`, port 8876,
  UID/GID 997, bounded cgroups, no automatic restart, new API/internal keys.
- Only a new synthetic `bcc-staging` project is granted; no existing project
  ACLs, production service, tunnel or production key is changed.
- Ten source credential/config files are copied only to their matching private
  worker profiles during owner installation. No provider credentials were
  included in the prepared capsule. Originals are not modified. Per-launch
  profile screening still strips unrelated hooks, MCP and settings.
- The helper is data-only as root; release code executes only under UID 997.
  It pins all control inputs, verifies archive members/file hashes, refuses
  existing installations, checks account/groups/host/port, and preserves any
  failed installation for inspection. Do not blindly rerun after a partial
  installation failure.

The full 1293-file capsule manifest and relocated non-editable import were
verified before installation. Source/control and credential-source metadata
checks passed without reading credential contents. Live cgroup startup,
per-provider tasks, quota/refresh status, cross-account denials and rollback
remain production HOLD gates. New source remains isolated and uncommitted.

## Source and preserved candidate

- Feature: `a7dev-autodiscovery-20261022` at
  `1e315608a13fe0db0a48e3dd6d1a5f981f1750b8`.
- Main: `e425c0c4dbc12cd29874e04b91586fe4a5458974`.
- Integration: clean, uncommitted merge of main into the feature snapshot in
  `/tmp/agentporter-bcc-production-XCkSZH`. The live repository's source files
  were not switched or replaced because production imports its editable venv.
- Durable local artifacts:
  `artifacts/bcc-production-readiness-20261027/` in this repository (ignored).
  They include the full candidate source, exact source-file manifest, wheel,
  locked requirements, synthetic staging smoke script/result, test logs,
  staged Bubblewrap source/binary, and candidate metadata. No production or
  provider credentials were copied into these artifacts.
- `candidate-source.tar.gz` SHA256:
  `a9becdc5b5346c0df0e0d52dc8a52202e602b50479a4284c6757fb5b7798cbe1`.
- Wheel SHA256:
  `7332fd35f77fc90eda4ffc589d641e1a86e640c83924cddcd6ece9fb54a79e0f`.
- All 76 wheel package files match the candidate source exactly. The source
  archive includes the new process-handle test that is not yet in Git's index.
  The archive and manifest, rather than the tracked-only patch, preserve the
  complete candidate.

## BCC inventory — executed locally

- Host: `pho-rdpdl-23`, Pop!_OS 22.04, kernel `7.1.1-76070101-generic`.
- Owner: yeli, UID `2056259175`, GID `2056259276`.
- `agentporter.service`: active; observed MainPID `2686385`; imports
  `/home/yeli/repos/AgentPorter/.venv/bin/agentporter`.
- `bcc-tunnel.service`: active; observed MainPID `1644330`.
- Gateway listens on `127.0.0.1:8765`. Health returned 200; unauthenticated
  deploy-info returned 401.
- No immutable release tree or installed trusted deploy helper was found at
  the paths documented by `docs/deployment.md`.
- No existing `agentporter-dev` or `agentporter-bcc-worker` account was found.
- Systemd 249; Bubblewrap 0.6.1; system Python 3.10.12; Python 3.13.18 is
  separately installed and used for candidate validation; uv 0.12.12.
- Git, ripgrep, patch, R, getfacl and setfacl are installed.
- Recorded jobs: 104 completed, 27 failed, 13 cancelled, 3 timed out; no
  active jobs were observed in the read-only snapshot. Recheck before cutover.
- Existing registry has 14 entries, including writable `repos`, AgentPorter
  and Obsidian entries. Do not transfer these broad grants mechanically into
  the production worker allowlist. Host-local scope must be explicitly reviewed.
- `sudo -n true` requires a password. Passwordless apt authorization does not
  authorize arbitrary root account/service installation and must not be used
  as a workaround.

## Candidate corrections

1. Prefer Python's descriptor-based `os.pidfd_open` and
   `signal.pidfd_send_signal`; retain libc fallback for Python builds without
   those APIs. BCC's glibc lacks the symbols the original code required.
   No numeric-PID signalling fallback was added.
2. Defer the three historical Asgard launcher `cd` operations until actual
   execution, after their source-only return guards. Refresh their parent
   checksum pins. Synthetic function tests no longer require an Asgard path.
3. Isolate the snapshot relocation test from the hardcoded Asgard checkout
   and an unbounded copy of a distro interpreter's `/usr` prefix.
4. Return sanitized HTTP 400 for invalid tool arguments instead of HTTP 500.
   Regression coverage includes traversal, absolute paths and sensitive paths.
5. Add Python 3.13 to CI; mark the Asgard-only Python 3.13 snapshot test as
   such on the other supported Python versions. Remote CI has not run for
   this uncommitted candidate.

## Verification and limitations

- Initial native full suite: **95 failed, 1959 passed, 21 skipped**, 24
  subtests passed. Those historical failures must not be mistaken for the
  corrected candidate's result.
- Corrected native run before the HTTP follow-up: **12 failed, 2045 passed,
  21 skipped**, 24 subtests passed. All 12 failures require the missing
  `--disable-userns`/`--assert-userns-disabled` Bubblewrap features.
- The exact 12 worker-boundary cases passed with Bubblewrap 0.13.1 substituted
  only in an ephemeral mount namespace; one additional environment-specific
  case was skipped. These use synthetic worker credentials. They do not
  establish provider authentication or end-to-end production delegation.
- A full-suite run inside that substitution namespace is not a valid native
  gate: namespace UID mapping hides root ownership and causes trusted-directory
  checks to reject fixtures. Its failures were not worked around by relaxing
  ownership checks. Use the native run and the explicitly bounded worker run
  as separate evidence; do not report a single green full suite.
- 30 native process/output/cancellation/Git tests passed; 88 installer and
  interpreter portability tests passed; 32 HTTP/interpreter/process regression
  tests passed after the HTTP correction.
- All six standalone offline security verifiers passed, covering HTTPS,
  routing, audit regressions, relay ownership/idempotency, credential refresh
  with synthetic inputs, and immutable shared resources.
- Non-editable wheel staging on an ephemeral BCC loopback port passed health,
  authentication, workspace scope, file read/write, traversal rejection,
  native offline execution, networking/publication denials and loaded/disk
  fingerprint checks. Staging used its own synthetic API key and workspace.
- Staged loaded/disk fingerprint:
  `de39efcf216a7824190a59026b810fd762f33e44bc7858537cd163881437b4d2`.
- One upstream Starlette/AnyIO deprecation warning remains. Skips and missing
  live acceptance remain explicit limits, not production passes.
- Final post-HTTP-change native result: **12 failed, 2048 passed, 21 skipped**,
  24 subtests passed, one upstream warning. The same 12 cases fail solely on
  the installed Bubblewrap feature gap. See
  `agentporter-bcc-production-native-final.log` in the artifact directory.

## Remaining rollout gates — NOT verified

1. Install a reviewed newer sandbox and configure its effective executable.
   The current runtime pins `/usr/bin/bwrap`; a binary sitting in `/tmp` is
   not an installation. Do not strip namespace restrictions to support 0.6.1.
   Staged upstream version: 0.13.1. Source SHA256, matching the upstream release
   asset digest: `0e85c8702248b8dd64144f594147553650cdd0e4c951690345faace79c217c4d`.
   BCC-built binary SHA256:
   `10d4f16697cbb3b77cc7c7b18ea56c811cd4978f069c9baad02f6777d84565fd`.
2. Provision an isolated immutable BCC worker tier under a separate account.
   No worker may run as yeli or inherit production config, state, provider
   accounts, credentials or host networking wholesale. The current development
   runtime explicitly refuses the production UID. Do not point BCC at mutable
   Asgard A7Dev.
3. Supply a reviewed cgroup-v2 launch arrangement for systemd 249. The current
   resource code expects the gateway in a `supervisor` child of
   `agentporter-development.service`. BCC lacks systemd's newer
   `DelegateSubgroup` directive. A compatible independently checked bootstrap
   or approved platform upgrade is required, followed by actual kernel-budget,
   cancellation, descendant-cleanup and rollback tests.
4. Review exact BCC workspace roots and public/worker grants, immutable runtime
   and toolkit paths, private separate credentials and provider-origin rules.
   Historical Asgard installers and credential mappings are not BCC installers.
   Confirm each requested provider using its own account; report quota and
   authentication failures individually. No model substitution was performed.
5. Define and test the production-to-worker interface. The existing production
   relay is read-only; writable public development delegation is a separate
   path. Do not imply the relay already supports writable delegated work.
6. Pin and independently review the final source/artifact; run CI and a complete
   native gate with installed prerequisites. Account for every skip. Re-run
   authenticated public MCP and negative credential/scope/publication checks
   against the exact frozen BCC staging release.
7. Prepare the owner-controlled immutable production install, preserve current
   service/config/state/tunnel and rollback target, rehearse rollback, and
   verify production fingerprints and the correct BCC ingress after cutover.

The next safe stage is the BCC worker installation design and privileged
ephemeral staging. Production cutover must wait for the above acceptance gates.
This report is not an activation instruction or a production readiness claim.

## Pickup update — staging update prepared, not installed

The candidate at `/tmp/agentporter-bcc-production-XCkSZH` includes the fix for the final launcher check selecting `/opt/agentporter-bcc/bin/bwrap`, and screened Codex model metadata. A fresh host run of its focused launcher and model tests passed 46 tests. A pinned staging update helper and wheel are in `artifacts/bcc-stage-20261027-04/`; the helper has not been installed or run as root. Its admission guard was exercised against a synthetic SQLite database, and update/rollback/recovery control flow was exercised with mocks; neither is a live rollback rehearsal. `sudo -n true` requires a password. Production gateway and tunnel were active in the user systemd instance when checked. Production rollout remains on hold pending staging update, live provider acceptance, rollback, and production install validation.

Fresh complete candidate suite with `AGENTPORTER_TEST_BWRAP=/opt/agentporter-bcc/bin/bwrap`: 2107 passed, 21 skipped, 24 subtests passed; one Starlette/AnyIO deprecation warning. The prior run without that selection failed 13 tests because the test fixture chose older `/usr/bin/bwrap`, which lacks `--disable-userns`.

## Live staging acceptance after release 04

The owner ran the release 04 update and `new -> old -> new` rollback rehearsal successfully. Release 04's authenticated fingerprint and boundary suite passed, including workspace scope, network/publication denial, process-tree timeout, and capacity reuse. Seven executable probes passed. Prof and Ming completed real confined provider calls and returned the synthetic README checksum. Liz's account reported its usage limit. Jax failed to reach its configured Headroom route; Phil could not reach GitHub's account-validation endpoint, which the current provider-origin rules omit. Wei returned an upstream-style unexpected server error; Argie returned 403. These failures are not fully diagnosed as provider versus policy failures. Production remains unchanged and on hold.

A candidate-only Phil policy adjustment adds only `GET https://api.github.com/copilot_internal/user`; its focused provider broker suite passed 81 tests, including denials for other GitHub paths and methods. It has not been packaged or tested in staging. The other route failures and a production release/rollback installation remain outstanding.

## BCC project discovery — implementation in progress

User requested automatic enrollment of all repository projects with read/write, offline execution and writable agent delegation. A BCC-specific draft adapted from the A7Dev helper and synthetic tests are preserved under `artifacts/bcc-project-discovery-draft/` and in `/tmp/agentporter-bcc-production-XCkSZH`. It has not been installed or run against the real projects. Host tests: 78 existing and BCC discovery tests passed, and 3 BCC-specific tests passed including ACL protections. The existing helper limits all projects to one 100,000-entry/120-second ACL budget, while a content-free scan counted at least 171,419 visible entries in 35 project directories, with one project at least 100,000. The current draft can defer enrollment indefinitely and is not ready for installation. It also inherits explicit exclusions for the AgentPorter production checkout and obsidian; this does not meet the user's all-projects requirement. Production currently uses an editable source checkout, so granting that checkout writable access before production is moved to a reviewed immutable release would allow workspace edits to alter future gateway startup. Complete scalable, resumable ACL enrollment and resolve protected-project handling before installation. Do not run the Asgard installer or activate the draft.

## Frozen 1.0 acceptance contract and staging boundary finding

Pulled AgentPorter `main` to `8dec760` and read `docs/bcc-production-acceptance.md`. Qman was absent from `~/repos`; cloned `lennon-li/Qman` there, checked out at `f52581d` on main, and read its AGENTS.md. No Qman files were changed.

Live release 05 staging test (synthetic, newly created repository): a public `exec/run` job initialized a nested Git repository, staged a synthetic file, and created a commit successfully without an approval receipt. The HTTP request returned 200 and exit code 0. This is a demonstrated failure of AP-05's unauthorized commit/process-bypass criterion; direct Git API denials alone do not enforce it. The job was limited to the synthetic staging workspace. Existing workspace-discovery code must not be activated until this boundary is addressed, and the same finding must be independently retested against the final running release. A separate synthetic same-job `.env` write/read also succeeded; that test alone does not prove exposure of existing real credentials.

Added a reproducible synthetic regression in the candidate `tests/security/test_scoped_git_metadata.py::test_generic_shell_cannot_commit_in_new_nested_repository`; it fails on the host because the unauthorized commit succeeds. A snapshot of the test is in `artifacts/bcc-project-discovery-draft/test_scoped_git_metadata.py`. A remedy must protect the actual process/filesystem boundary, not just reject a `git` command string, and must preserve the separately authorized commit workflow in AP-03.

## Unauthorized Git bypass investigation

A host probe verified Bubblewrap 0.13.1's writable overlay: a synthetic job changed only its upper layer while the original lower file remained unchanged. A candidate-only validator rejects Git/sensitive path changes, symlinks, hardlinks, and overlay opaque/whiteout metadata; nine focused tests passed, including a synthetic nested commit in a real overlay that the validator rejected without modifying the lower tree. This is an isolated component, NOT a fix in the running gateway: it is not connected to generic job or agent lifecycles, has no safe delta publisher, and has not addressed concurrent changes, cancellation/recovery, authorized commit receipts, or ephemeral commits elsewhere. The live nested-commit bypass and AP-05 blocker remain. No production or staging release was changed.

Follow-up: a real normal overlay copy-up on BCC carries `user.overlay.origin`; the draft validator now permits that inert origin marker while rejecting other overlay metadata, symlinks and hardlinks. Ten focused tests passed on the host. The eventual publisher must not propagate overlay xattrs and must perform descriptor-safe, conflict-checked publication after verified job-tree termination. This prototype is not wired into either job path and does not fix the live bypass.

## Canonical-history boundary verification (Jax continuation)

Correction to the earlier nested-commit finding: constructing Git data in a new disposable repository alone does not establish unauthorized mutation of a registered project's history. That original test has been corrected to permit the disposable computation. AP-05 must protect canonical history and independently authorized publication.

Two more precise, synthetic host regressions now demonstrate actual canonical-history mutation in the integrated candidate:

- `test_generic_shell_cannot_change_existing_nested_repository_history`: a generic command changes an existing nested repository's HEAD. FAILED as expected before remediation.
- `test_generic_shell_cannot_change_canonical_ref_through_hardlink`: an ordinary-looking writable hard link aliases the root repository's protected branch ref; writing the alias changes HEAD despite the read-only `.git` mount. FAILED as expected before remediation.

These failures prove that recursive `.git` mounts alone cannot satisfy the boundary. They do not imply that real project history was changed: the tests use disposable synthetic fixtures only.

A real BCC Bubblewrap overlay probe now reproduces the hard-link attack against private copy-on-write storage and verifies that both lower-layer aliases and the canonical ref remain unchanged. The focused overlay validator/probe suite passes **11 tests**. This demonstrates the storage primitive, not end-to-end protection: job integration, quiescent validation, conflict checks, descriptor-safe atomic replacement (never writing through existing destination hard links), cancellation/recovery, and separately authorized Git operations remain unfinished. No live service or workspace access configuration was changed in this continuation.

## File application primitive (candidate only)

Added `publish_workspace_file` to the candidate delta module, with tests written and observed failing before implementation. This internal primitive creates or atomically replaces one ordinary file. It rejects protected/escaping paths, symlink parents/sources, nonregular files, multiple-link destinations/sources, privileged modes, oversized inputs, absent/stale expected digests, and detected changes during inspection. Creation uses create-only hard-link semantics; replacement uses a new inode, never writes through an existing destination alias. Parent traversal uses directory descriptors and O_NOFOLLOW. Temporary output is fsynced, replacement is followed by a parent fsync, and temporary files are cleaned on prepublication failures.

Preconditions remain explicit: caller-controlled exclusive workspace mutation lease, complete job process termination, exclusive custody of the validated delta. It does not supply these guarantees, authorize Git/network publication, or implement a multi-file transaction or recovery journal. No job uses it yet. Do not expose real projects based on these primitive tests.

Verification executed on BCC: **23 passed** across the complete overlay/delta and file-application test files; **6 passed** for existing scoped Git behavior excluding the two documented canonical-history regressions, which remain failing. Candidate `git diff --check` and Python compilation passed. The source/test snapshot is preserved in `artifacts/bcc-project-discovery-draft/`. Live staging and production remain unchanged.

## Shared secret-path policy and cleanup integration inspection

The candidate delta validator and single-file application primitive now call the same `check_sensitive_components` policy as workspace path validation, rather than maintaining a narrower duplicate blacklist. Ten observed-failing regressions exposed `.envrc`, `*.key`, `*.pem`, `.config/github-copilot`, and `.local/share/opencode` gaps; all ten now pass. The existing private path helper was promoted to a public module function and its internal callers updated. Full relevant verification: **38 passed** across `test_paths.py`, `test_workspace_delta_guard.py`, and `test_workspace_file_publication.py`, including actual BCC overlay probes. `git diff --check` passed; no stale references to the former private function name remain.

Lifecycle inspection confirms `ResourceLease.close()` is the existing quiescence proof: it kills the owned cgroup, verifies `populated=0`, then removes the envelope. `terminate()` alone does not prove cleanup. Async job finalization already retains admission on cleanup failure, and synchronous sandbox execution closes its lease before returning. Transaction publication must run only after that proof, keep workspace serialization through durable finalization, and bind the correct workspace/delta to the job. Agent launch preparation remains a separate integration path. No transaction hook was added prematurely; job storage/publication integration remains unfinished.

## Synchronous transaction integration — opt-in candidate mode

Added `WorkspaceTransaction` and connected it to `BubblewrapSandbox.run` behind the internal `transactional_writes` constructor flag. This flag remains false by default and is not enabled in any deployed service. Generic writable synchronous execution in this mode requires a resource envelope and the verified root-owned BCC Bubblewrap executable. The transaction replaces the authorized workspace bind with a private overlay, masks existing protected secrets, records bounded baseline hashes, and holds a workspace-inode-keyed exclusive lock. Only successful execution proceeds to validation/application after `_run_command` completes its resource cleanup. Failed commands discard private writes; cleanup uncertainty retains private state and the lease. The existing trusted Git metadata mutation route remains separate and must share workspace serialization before production enablement.

Application validates the whole upper layer before writing, preflights changed-file hashes against the baseline, creates directories through no-follow descriptors, and invokes the tested atomic single-file primitive. A durable, fsynced pending journal guards publication. A publication interruption retains private data and blocks subsequent transactions, including after the original lock is lost; owner recovery tooling is still required. Deletion/opaque overlay deltas remain rejected. Queued jobs, agent launch, direct mutation tools, common serialization, recovery operations, and production configuration integration remain unfinished. Do not enable this opt-in mode for all project access yet.

Real overlay tests cover delayed ordinary-file application, nested canonical Git-ref rejection, owner edit conflict preservation, secret masking, transaction serialization, canonical-ref hard-link rejection, failed-job discard, and retained durable publication guards. Resource cleanup integration uses a recording resource lease to test ordering/failure behavior; this is not an independent live-cgroup acceptance result. **50 focused tests passed**, compilation and `git diff --check` passed. Inert overlay UUID/impure/origin metadata is permitted but not copied to project files; redirection, metacopy, whiteout, and opaque controls remain denied.

The first complete suite had 2,156 passed, 21 skipped, 24 subtests passed, two expected direct-bind canonical-history failures, and one fixture-path failure: the long chosen `--basetemp` caused AF_UNIX path length overflow in the provider broker test. Full revalidation with a shorter test root was started; its final result must be recorded separately. Source/test snapshots and SHA256s are preserved in `artifacts/bcc-project-discovery-draft/transaction-source-snapshot.json`.

Full candidate revalidation completed using short fixture root `/tmp/ap-bcc-tx`: **2,157 passed, 21 skipped, 24 subtests passed; 2 failed** in 71.91 seconds. The only failures are the two deliberately retained canonical-history regressions against the legacy/default direct-bind execution path. The provider-broker test passes with the corrected fixture path. One existing Starlette/AnyIO deprecation warning remains. This is a failing overall suite, not a production acceptance PASS. The opt-in transaction suite passes independently; migration of queued/agent execution and shared mutation serialization is the next integration step. Cancellation/finalization must use an atomic job-state transition so an accepted cancellation cannot race edit publication; admission must treat finalization as nonterminal.

## Queued command integration — opt-in candidate mode

Connected `exec_start` to `JobManager.start_transaction_job` when the sandbox's internal transaction mode is enabled. The launcher requires sandbox/manager to share the same resource provider, creates private storage before spawn, registers transaction ownership before starting the monitor, and persists its transaction directory with the job record. Legacy/default behavior and all deployed services remain unchanged.

After verified process/resource and prepared-launch cleanup, the monitor atomically claims `running -> finalizing` before applying edits. An already accepted cancellation wins the claim and causes private edits to be discarded. If finalization wins, cancellation returns `finalizing` without claiming cancellation was accepted. Admission treats finalization as nonterminal. Rejected deltas fail the job with a bounded log notice; publication or cleanup uncertainty retains private data, the workspace lease, and admission. Restart distinguishes process recovery from uncertain edit application and preserves admissions for finalizing or transaction-publication failures. Persisting transaction identity fixes an observed-failing regression where startup previously cleared a failed publication's admission.

Verification executed on BCC: **89 passed** across transaction, shared path policy, async bounds, process-tree cancellation, resource closeout, and offline-default tests. Tests cover direct execution-tool routing, successful edit application before terminal status, nested canonical Git-ref rejection, failed command discard, accepted cancellation, cancellation/finalization races, retained admission during finalization, and durable publication guards across simulated restart. Resource tests use recording providers for lifecycle ordering; real live-cgroup and independent acceptance remain unverified. A complete suite run is in progress; its result must be appended separately.

Remaining integration work still includes agent launch, read-only secret visibility, common locking for trusted Git/direct mutation tools, durable owner recovery operations, production configuration, and live staged verification. Do not enable real project enrollment based only on this opt-in command-path progress.

Queued integration full-suite result: **2,165 passed, 21 skipped, 24 subtests passed; 2 failed** in 72.36 seconds. Only the two retained canonical-history regressions on the legacy/default direct-bind path fail. One existing Starlette/AnyIO deprecation warning remains. `git diff --check` passed. The overall suite and production acceptance remain failing/incomplete; all transaction mode behavior described above is opt-in candidate behavior only. Full test output is retained at `/tmp/agentporter-full-async-transaction-20261027.log`.

## Native delegated agent transaction integration — candidate only

Added opt-in transaction support to `DevelopmentRuntime.prepare/_build` and `JobManager.start_confined_agent_job`. Writable agents in this mode require a resource provider. Their workspace overlay uses the existing pinned runtime workspace descriptor, verifies that descriptor against transaction identity, and preserves the runtime's executable/credential checks and descriptor-closing worker wrapper. Transaction ownership and durable directory identity are registered before monitor launch. Agent edits then use the same post-cleanup, cancellation-aware finalizer as queued command jobs. Preparation/start failures discard private data only after verified process cleanup; cleanup uncertainty retains the transaction.

A newly observed-failing root-replacement regression proved that pathname-based finalization could apply edits to a substituted directory. Transactions now retain a separate CLOEXEC root descriptor through finalization, reject a changed registered root identity, and perform publication through that retained descriptor. This descriptor is not passed to agent processes. Crash-simulation tests now close both simulated-owner descriptors when modeling owner-process loss.

Focused verification on BCC: **153 passed, 1 skipped**, covering native runtime/delegation regressions plus all synchronous/queued transaction lifecycle tests. Synthetic native worker tasks prove ordinary edits remain private until finalization and are then applied; failed workers and protected new-Git deltas leave project contents unchanged. This does not prove real Liz/provider success or AP-02 identity acceptance: fixtures use configured synthetic Python workers and synthetic credentials. Compilation and `git diff --check` passed. BCC-specific integration modules now explicitly skip where the installed BCC sandbox is absent; they execute on the BCC target. Full candidate revalidation is in progress.

Still unfinished before production enablement: generic command lower mounts/baseline traversal must converge on pinned descriptors, read-only command secret visibility must be covered, all mutation tools must share workspace serialization, and owner recovery/configuration/live acceptance must be implemented. Existing deployed services still use their prior release and configuration.

Native integration full-suite result: **2,170 passed, 21 skipped, 24 subtests passed; 2 failed** in 73.14 seconds. The only failures remain the two retained canonical-history regressions against the legacy/default direct-bind command path. One existing Starlette/AnyIO deprecation warning remains. The overall suite and AP-01–06 production acceptance are not passing. Full output: `/tmp/agentporter-full-agent-transaction-20261027.log`. No staging/production activation, commit, or push occurred in this continuation.

## Pinned generic mounts, read-only protection, shared locks, configuration

Generic synchronous and queued transaction-mode commands now mount the retained workspace descriptor, pass it only through sandbox setup, and use a fixed worker wrapper that closes inherited descriptors before executing the requested command. Existing Git metadata overmounts are redirected through the pinned source too. Baseline traversal uses the retained descriptor, rather than re-opening the registered pathname. A prepared command continues to read the original inode after pathname replacement; publication still rejects the replaced registered root.

Read-only generic jobs now use the same secret visibility scan and pinned source, with a read-only workspace mount and read-only empty masks for sensitive directories. They do not publish deltas. An observed-failing regression showed a secret hard-link alias could bypass a read-only filename mask; all modes now reject regular-file inode aliases before launch. Existing secret masking permits ordinary authorized edits without changing or exposing the secret.

Baseline capture records device/inode/mode/link count/size/mtime/ctime metadata instead of hashing every file. Only changed files are hashed during preflight, with baseline identity/metadata verification before hashing and stable-file checks during reads. This preserves owner-conflict detection while allowing ordinary code edits in projects containing untouched large scientific data. Changed-file application retains its 64 MiB bound. Baseline traversal is bounded to one million entries and 30 seconds; over-budget jobs fail closed. A sparse 65 MiB untouched scientific-data regression passes.

Added a shared inode-keyed mutation lease and recovery guard to all five file-mutation tools and all trusted Git mutation entry points in transaction mode. These use the same key/lock namespace as jobs; active jobs block competing mutations, and pending publication journals block every file mutation even after the original lock is gone. The new strictly boolean `sandbox.workspace_transactions` configuration switch wires synchronous commands, queued commands, delegated agents, and file/Git serialization together. Enabling it without hardened resource supervision refuses startup. It is false by default and has not been enabled in deployed services.

Verification: **222 passed, 1 skipped** in the first broad pinned/delegation/cancellation/resource suite; after additional alias/large-data/configuration/guard tests, **76 focused tests passed**. The first complete run exposed compatibility failures in legacy sandbox test doubles (missing or Mock-valued mode attributes); these were corrected by treating only explicit boolean True as transaction mode at tool construction. All 12 affected Git permission/publication tests pass. Final complete candidate suite: **2,193 passed, 21 skipped, 24 subtests passed; 2 failed** in 74.05 seconds. Only the two legacy/default direct-bind canonical-history regressions remain failing. One existing Starlette/AnyIO deprecation warning remains. Compilation and `git diff --check` passed. Full result: `/tmp/agentporter-full-pinned-final-20261027.log`.

Restored cleanup permissions on two specifically identified stale synthetic overlay test work directories from this session; no unrelated files were removed. Current source/test snapshot hashes are in `artifacts/bcc-project-discovery-draft/transaction-source-snapshot.json`.

Outstanding production work: owner recovery operations for durable partial publication, independently authorized Git repository workflows, scalable project enrollment/immutable production migration, actual provider-route failures, staged activation, and the independent frozen AP-01–06 audit. Transaction mode has not been deployed or certified. Existing live services remain unchanged.

## Trusted Git filters and pending-publication owner recovery

A new synthetic regression demonstrated that a repository smudge filter could create a canonical commit/ref during an allowed checkout despite the hook guard. Trusted metadata-writable Git operations now perform a bounded, in-sandbox configuration inspection and refuse executable clean/smudge/process filters, including included configuration. Submodule recursion is disabled. Normal staging/checkout/hook tests and included-filter rejection tests pass. This is a fail-closed restriction, not an independently authorized Git publication backend; commit/push approval work remains unfinished.

Added owner-only offline pending-publication recovery in `agentporter.sandbox.workspace_recovery`, with procedure in the candidate `docs/bcc-workspace-recovery.md`. The CLI requires the actual BCC worker identity and refuses root, verifies the service is stopped and its cgroup empty, and holds supervisor/workspace maintenance locks. It validates private journal/layout/schema, whole-delta eligibility, all current file states, and the job database before applying any file. The owner must provide the exact inspected plan SHA256. Conflicting owner edits are preserved, already-applied files are not replaced, pending files are applied atomically per file, and a durable receipt precedes clearing the journal. Matching job admissions are released; unrelated and still-unresolved unbound reservations remain held. Job status `recovered` is recognized across MCP/REST polling and the owner update guard. The command handles existing valid pending journals; missing/corrupt journals and other cleanup failures still require owner inspection rather than automatic clearance.

Ten recovery tests pass, including stale reviews, changed staged data, owner conflicts, invalid database preflight, live supervisor locking, and selective admission release. Three owner update-guard tests pass. Whole-delta validation now rejects oversized and privileged-mode files before any canonical publication. A host read-only guard invocation refused the actual running BCC worker service without modifying it. The recovery apply path has not been exercised under the real worker account in an offline service window.

Complete final candidate verification: **2,212 passed, 21 skipped, 24 subtests passed; 2 failed** in 74.75 seconds. The only remaining suite failures are the retained canonical-history tests against the legacy/default direct-bind path. An initial complete run also caught checked-in Actions schema drift for the new status description; the schema was synchronized and its three security metadata tests pass. One existing Starlette/AnyIO deprecation warning remains. Full log: `/tmp/agentporter-full-recovery-final-20261027.log`. Compilation and `git diff --check` passed.

## Blocking cross-owner kernel behavior — owner probe prepared

A real isolated overlay probe attempted a new private file inside a public, foreign-owned world-writable lower directory. BCC rejected copy-up with **EOVERFLOW / Value too large for defined data type**; the host source remained unchanged. Same-owner synthetic tests do not prove the real project workflow: BCC's worker is UID 997 while project files belong to UID 1000. Ownership normalization must be verified before real-project enrollment.

Prepared a bounded standalone root diagnostic at `artifacts/bcc-idmap-probe.py`, SHA256 **ca2c17d8426e3084b25b11dd4cf2325546e9c6e9d1c3585faeccd6e5e722e92f**. It creates a private mount namespace, creates a read-only idmapped view of the named AgentPorter project, drops the test process to UID/GID 997 with no-new-privileges, writes only a synthetic README in a temporary overlay, and verifies canonical README identity/content are unchanged. It neither changes services/configuration nor makes a host-visible projection mount. It checks the installed Bubblewrap hash/ownership and fixed BCC account identities and cleans its temporary mounts/data. The source compiles; its non-root refusal was exercised before mutation. Its privileged execution is **NOT VERIFIED**.

`sudo -n true` currently returns `sudo: a password is required`. The private idmapped-mount test needs owner sudo authentication. This is an OS credential requirement, not a request to broaden authorization. No installed service/release/configuration was changed. Do not treat the new transaction mode as production-ready until this cross-owner lower-layer issue, independently authorized Git operations, enrollment/cutover, provider failures, and frozen acceptance audit are resolved.

## Failed-job private-directory cleanup correction

Observed and fixed a reproducible cleanup failure: a job created a private directory with mode 000 and exited 7; cleanup raised PermissionError before releasing its workspace lock. Private cleanup now restores directory access only through pinned no-follow directory descriptors, checks ownership, skips symlink targets, and retains the bounded depth/entry/time scan limits. It then removes the private transaction tree and releases descriptors/locks. Cleanup errors are normalized to ResourceCleanupError; synchronous execution retains the transaction object so admission stays held when cleanup remains uncertain.

New regressions prove the failed job preserves its exit code, makes no canonical directory, and permits a clean subsequent edit job. A separate test proves an outside directory reached through a staged symlink does not have its permissions changed. Verification: **33 transaction integration tests passed**, followed by **74 passed** across updated transaction, owner recovery, resource closeout, process-tree cancellation, and asynchronous log-bound suites. `git diff --check` passed. This is candidate-only; services remain unchanged.

The root idmap probe has not yet been installed at `/usr/local/libexec/agentporter-bcc-idmap-probe.py`. Its required owner result remains unavailable. The source artifact SHA256 remains `ca2c17d8426e3084b25b11dd4cf2325546e9c6e9d1c3585faeccd6e5e722e92f`. Cross-owner copy-up remains a deployment blocker; no successful idmapped projection or production acceptance result has been claimed.

## Liz pickup — Git receipt ledger hardening

Resumed Jax session `01a17ec1-a7da-78b2-9498-22c2b9d335f8` after the owner
explicitly resumed its paused BCC production objective. The candidate remains
at `/tmp/agentporter-bcc-production-XCkSZH`; the live editable checkout was not
replaced. The receipt primitive had not yet been connected to Git execution.

Native regressions demonstrated that verification accepted a ledger directory
after its permissions became public, and accepted unsafe SQLite sidecars.
The candidate now rechecks private parent permissions and filesystem identity
on every claim, and rejects symlinked, hard-linked, public, foreign-owned, or
nonregular journal/WAL/shared-memory files before SQLite opens them. Constructor
checks cover pre-existing sidecar aliases too. Tests preserve unrelated owner
data and prove rejection does not consume a valid receipt. Added replacement
directory and constructor-alias regressions alongside the existing scope,
signature, expiry, tampering, and concurrent replay checks.

The receiver sandbox maps root ownership to UID 65534, causing the verifier to
refuse its ancestors. Native BCC test execution was used instead; no ownership
guard was relaxed. A combined native receipt/Git/REST run had **65 passed and
2 failed**: the same retained legacy direct-bind canonical-history failures.
The receipt file contributes **37 passing tests**. Compilation and
`git diff --check` passed.

The candidate's `docs/bcc-git-approval-protocol.md` records the receipt trust
boundary and remaining backend requirements. Commit/push/fetch/pull remain
locked through the shared tools. The signer and protected backend, scoped Git
transport, actual repository-state inspection under the mutation lease, and
MCP/REST receipt integration remain unfinished. This hardening does not enable
or certify authorized Git execution.

Source, tests, protocol notes, and SHA256 manifest are preserved under
`artifacts/liz-bcc-git-approval-20261027/`. Native service checks confirmed the
user `agentporter.service` and `bcc-tunnel.service` are active, as is the system
`agentporter-bcc-worker.service`. The ownership probe remains uninstalled at
its trusted root location; its source hash is unchanged. No service, release,
workspace grant, or deployment configuration was changed.

Final native suite with the installed sandbox selected using
`AGENTPORTER_TEST_BWRAP=/opt/agentporter-bcc/bin/bwrap`: **2,251 passed,
21 skipped, 24 subtests passed; 2 failed**, in 74.51 seconds. Only the retained
legacy direct-bind nested-history and hard-link-ref regressions failed. One
existing Starlette/AnyIO deprecation warning remains. Log:
`/tmp/liz-bcc-full-installed-20261027.log`, also copied into the artifact
directory above. The initial run without the installed sandbox selection had
2,236 passed and 17 failed; 15 failures selected obsolete distro Bubblewrap
and rejected its missing `--disable-userns` option. Neither run is production
acceptance or proof of successful real provider calls. All AP criteria remain
subject to the frozen independent live audit.

## Locked repository-state capture and receipt consumption — candidate only

Added `src/agentporter/git_approval_state.py` in the isolated candidate. Its
`locked_git_request` context captures the actual repository identity, HEAD,
branch, and staged tree while retaining the shared workspace mutation lease.
Inspection runs inside the existing read-only, network-isolated sandbox.
It computes staged trees using a clean scratch Git directory, copied index,
and read-only alternate object store; canonical index/object files are not
written. Fixed read commands disable hooks and fsmonitor. Clean scratch
configuration prevents original repository configuration from controlling tree
construction or HEAD object-type checks. Index copies share a 64 MiB budget
and at most 128 shared indexes. SHA1/SHA256, unborn repositories, empty indexes,
and split indexes are covered. External Git directories/linked worktrees are
explicitly refused by this initial inspector; final workspace enrollment must
resolve or represent that unsupported layout.

The `approved_git_request` context constructs the expected request from this
state, consumes the exact owner receipt, and retains the same mutation lease
through its body. Changed staged state cannot consume an earlier approval;
replay fails and failed execution cannot restore a claimed receipt. This is an
internal context, not a public Git backend, and performs no Git mutations.
Keys, registry, verifier, and sandbox must come from protected backend policy.
Actual execution must still be implemented with pinned repository descriptors,
appropriate state revalidation, bounded metadata access, and scoped transport.
The direct public Git publication/network tools remain locked.

Regressions caught and corrected recursive lock acquisition when transaction
mode is configured, missing-root errors during identity revalidation, approval
of an index containing missing blobs, and HEAD values naming missing or
non-commit objects. Read-only inspection uses the existing bounded command
primitive inside the already-held lease; configured resource supervision and
cleanup still execute. Pending publication/recovery blocks inspection. Receipt
expiry is now rechecked after acquiring SQLite's write lock so a wait cannot
admit a receipt that expired before its claim.

Final focused native verification: **94 passed** across state capture, signed
receipt verification/consumption, mutation serialization, workspace
transactions, and public Git publication denials. Tests include repository
root replacement/removal, unsafe metadata, resource cleanup, and no canonical
metadata changes during inspection. Compilation and `git diff --check` passed.
Artifacts: `artifacts/liz-bcc-git-state-20261027/`, including source, tests,
protocol notes, logs, and SHA256 manifest. This work changes no running
service, deployment configuration, provider account, or workspace grant.

Final native full suite with BCC's installed sandbox explicitly selected:
**2,274 passed, 21 skipped, 24 subtests passed; 2 failed**, in 76.96 seconds.
Only the retained legacy direct-bind canonical-history/hard-link-ref tests
failed; the same Starlette/AnyIO deprecation warning remains. Log:
`/tmp/liz-bcc-full-git-state-final-20261027.log`, preserved as
`native-full-final.log` in the artifact directory. The earlier intermediate
full run had 2,271 passes and the same two failures before the missing-object
and HEAD-type regressions were added and fixed. Neither is a production
acceptance PASS. The active goal remains incomplete; the next implementation
step is the protected Git mutation backend and its exact-operation tests.

## Exact owner-approved commit backend — internal candidate

Implemented `agentporter.git_commits.ApprovedGitCommits` in the isolated
candidate. Protected backend dependencies supply the registry, sandbox,
verification ledger, and author identity. Preparation binds author/committer,
message, UTC timestamp, repository identity, branch, HEAD, and actual staged
tree. Execution re-inspects state under the shared mutation lease and consumes
only its exact signed receipt. Detached HEAD is explicitly refused by this
initial backend; initial commits and SHA256 repositories are covered.

Only pinned `.git` metadata receives canonical write access. Ordinary workspace
files stay read-only, network is isolated, and original repository config is
hidden behind sealed clean config mounted using Bubblewrap's `--ro-bind-data`.
The first launch test caught that ordinary `--ro-bind` cannot resolve the
anonymous memfd source; it was corrected without exposing writable config.
Metadata inspection rejects symlinks, hard links, special files, nested mount
boundaries, active lock files, external object alternates, common directories,
and reftable layouts. Host directory descriptors are closed before the fixed
Git script executes. Hooks, filters, external signing, inherited config, lazy
fetching, and replacement objects cannot extend its authority.

The fixed script verifies current HEAD/branch/staged tree, creates the exact
approved commit via `commit-tree`, and compare-and-swaps only the approved
branch through `update-ref`. BCC Git 2.34 lacks newer `core.fsync`; it supports
`core.fsyncObjectFiles`, used here alongside explicit ref/reflog and directory
syncs. A private durable success receipt is recorded before clearing the
durable Git-operation guard. The normal result includes a commit with the
expected tree/parent/author/time, clean staging state, and ordinary reflogs.

Every operation rechecks transaction-enabled resource supervision. A new
internal `require_resources` command option snapshots the resource provider and
fails closed if absent, preventing an unsupervised metadata-write fallback.
Tests first demonstrated the missing per-operation check, then verified the
correction. Owner changes after state capture are preserved; a replaced root
cannot receive the approved commit. Unknown launch/outcome, receipt-storage,
or resource-cleanup failures retain `.git-pending.json`. Shared mutation
leases and workspace transactions now refuse these guards after restart too.
Workspace-file recovery preserves unbound admissions while any Git guard
remains unresolved.

Native focused gate: **129 passed**, covering commits, actual-state approval,
receipt verification, mutation serialization, transaction/recovery guards, and
resource closeout. Native full suite: **2,292 passed, 21 skipped, 24 subtests
passed; 2 failed**, in 78.95 seconds. Only the existing legacy direct-bind
nested-history and hard-link-ref regressions failed. The existing upstream
Starlette/AnyIO deprecation warning remains. Compilation and `git diff --check`
passed. Exact source, tests, protocol notes, evidence logs, and verified SHA256
manifest: `artifacts/liz-bcc-approved-commit-20261027/`. Full log:
`/tmp/liz-bcc-full-approved-commit-20261027.log`.

This is not public API activation or AP-03 certification. Git guard recovery
is still unfinished; do not manually clear these guards or use workspace-file
recovery for them. Protected service/signing policy, admission/API integration,
scoped network Git transport, and cross-owner metadata ownership/permissions
still need implementation and real verification. Synthetic same-owner
repositories and recording resource providers do not prove those installed
boundaries. No running service, release, credential account, or workspace grant
was changed. The next implementation step is owner-controlled Git recovery.

## Owner reconciliation for interrupted approved commits — candidate only

Added `agentporter.git_commit_recovery` and the candidate procedure
`docs/bcc-git-recovery.md`. This offline owner CLI has no MCP/REST entry point.
It requires a stopped BCC worker service, an empty worker cgroup, exclusive
supervisor/workspace maintenance locks, private owner state, a matching
consumed ledger claim, and the exact reviewed plan hash before clearance.
Its ledger reopening mode never creates a missing ledger or restores a nonce.
It never creates/retries commits, rewrites Git history, stages files, deletes
Git lock files, or releases unrelated admissions.

The read-only plan derives the exact approved commit identity in scratch
storage from signed tree, parent, author/committer, timestamp, and message
bytes. Native inspection found Git's stdin commit message is preserved without
an added trailing newline; recovery was corrected against actual object bytes.
UTF-8 identity and branch regressions also caught ASCII-only Git output
decoding; inspection and commit execution now consistently decode UTF-8.
Tests cover SHA1/SHA256, initial and existing history, message newline variants,
and UTF-8 identities/branches.

Plans report `approved_commit_at_head`, `original_head`, or `conflict`.
`original_head` is an observation of the current ref, not a claim that a commit
never ran before an owner reset. For the approved-commit observation, actual
decompressed commit content must exactly match the approved object; matching
ref names backed by altered object bytes are a conflict. Conflicting owner
history, unknown consumed claims, changed roots, unsupported metadata layouts,
and unresolved Git locks refuse clearance. Durability checks persist observed
ref/reflog contents and relevant object/metadata directories. A durable private
recovery receipt precedes clearing only the selected Git guard; a failed sync
retains that guard. The spent signing receipt remains unusable.

Focused native verification: **118 passed** across recovery, approved commits,
actual-state capture, receipt/ledger verification, workspace recovery, and
mutation serialization. Tests prove reviewed clearance preserves history and
permits a newly signed subsequent commit, while stale plans, active supervisor
locks, unknown claims, owner conflicts, unresolved Git locks, altered objects,
and durability failures cannot clear the guard. A separate native CLI probe
using only temporary synthetic state and keys refused the actual running BCC
worker service; it made no service changes. Compilation and `git diff --check`
passed. Source/tests/procedure/logs and SHA256 manifest are preserved under
`artifacts/liz-bcc-git-recovery-20261027/`.

This does not certify installed recovery or production acceptance. Actual
offline maintenance under the deployed backend identity, protected signer and
service provisioning, public API/admission integration, scoped network Git
transport, cross-owner operation, and frozen live acceptance remain unfinished.
If the Git backend is installed in a separate service, its stopped/quiescent
lifetime must also be covered before this maintenance procedure can certify
that deployment. No running release, service, credentials, or project grants
were changed. The next implementation step is protected backend policy and
API/admission integration.

Final native verification after actual-content and durability checks:
**2,314 passed, 21 skipped, 24 subtests passed; 2 failed**, in 82.12 seconds.
Only the retained legacy direct-bind nested-history and hard-link-ref
regressions failed; the same upstream Starlette/AnyIO warning remains.
Final log: `/tmp/liz-bcc-full-git-recovery-durable-20261027.log`, copied as
`native-full-durable.log` into the recovery artifact directory. Earlier runs
before final edge-case coverage had 2,307 and 2,312 passes with the same two
failures; these are intermediate source results. The final artifact manifest
and live candidate source parity were verified. Production acceptance remains
incomplete; no AP criterion was certified by these development tests.

## Protected commit policy, durable admission, and authenticated API — candidate

Added `git_policy.py` and `git_admission.py` in the isolated candidate.
The fixed owner `git-commit-policy.json` supplies the verification key, existing
ledger, author identity, and explicit workspace IDs. Absence preserves locked
commit behavior. The loader checks trusted file/directory ownership and modes,
rejects aliases/unknown fields/wildcards, refuses a missing ledger, pins roots
by filesystem identity, and excludes configuration, state, ledger, and loaded
package paths from all exposed roots. Every request rechecks policy contents,
scope, identity, and protected-path separation. A changed/removed policy
revokes loaded authority until reviewed restart.

The shared `git_commit` interface now accepts `prepare_only`,
`approval_timestamp`, and `approval_receipt`. Preparation returns the exact
unsigned request; execution requires its independent signature and timestamp.
Implicit all-files staging is refused. REST forbids extra authority-selection
fields. No key, ledger, or policy path is chosen through an API argument.
MCP and REST call the same protected backend. Public clients require a separate
explicit `git_commit` scope; `git_write` continues to cover staging/checkout
only. Operator commit mode changes from LOCKED to APPROVAL only when the
protected backend loaded; permissive mode flags alone cannot enable it, and
owner LOCKED overrides still deny it. Push/fetch/pull remain locked.
Checked-in Actions request schemas were synchronized with live code.

Preparation and execution now use gateway capacity through the same manager
and resource provider. Version-2 Git guards bind a private admission token.
The guard is durable before its database binding, and no Git mutation launches
before that binding. Active `git_admissions` survive startup resource recovery;
otherwise startup would have discarded their unbound synchronous slots.
Verified cleanup and a durable success receipt resolve the exact reservation
before final guard deletion. Resolved binding records remain available for
safe retries if that final deletion fails. Errors after guard creation are
normalized to retained cleanup uncertainty instead of accidentally releasing
capacity through an ordinary exception.

Owner recovery validates the exact request/guard/token database linkage,
records a durable recovery receipt, resolves only that token, and clears the
guard. It can safely inspect a crash between guard persistence and database
binding as `unbound`. Corrupt bindings and asynchronous-job token aliases are
refused; unrelated reservations remain. Workspace-file recovery excludes
active Git bindings and remains compatible with databases predating the new
table. Tests cover restart retention, pre-binding interruption, exact capacity
reuse, changed bindings, and interruption after capacity resolution.

Focused native gate: **110 passed**, one existing upstream warning. Native
full gate: **2,339 passed, 21 skipped, 24 subtests passed; 2 failed**, in
85.05 seconds. The only failures remain the retained legacy direct-bind
nested-history and hard-link-ref regressions. Authenticated real-server MCP
and REST tests perform prepare/sign/commit against disposable repositories
using synthetic owner keys; resource supervision is a recording provider.
They verify missing/mismatched approvals, client scope, owner revocation,
authority injection denials, and exact resulting Git history. This is source
behavior evidence, not live BCC cgroup/provider/production acceptance.

Compilation, schema parity, `git diff --check`, and preserved source/artifact
parity passed. Procedure: candidate `docs/bcc-approved-git-api.md`. Source,
tests, schemas, procedures, logs, and SHA256 manifest are preserved under
`artifacts/liz-bcc-git-api-20261027/`; full log:
`/tmp/liz-bcc-full-git-api-20261027.log`. No protected policy, key, ledger,
service, release, or project grant was installed or changed on BCC. A fresh
`sudo -n true` still requires the owner password, so the cross-owner probe is
not yet executable by this session. Independent issuer setup, scoped network
Git transport, deployed cross-owner/resource verification, immutable rollout,
and all frozen live acceptance remain incomplete.

## Canonical write fallback removed; alias regressions fixed

The generic Bubblewrap builder now always starts with a read-only canonical
workspace mount. Supervised transactions replace it with their pinned private
overlay; generic commands never receive a writable lower bind. Fixed trusted
Git tools retain their separate metadata write boundary. `get_capabilities`
reports `sandbox.workspace_access` as `read-only` or `transactional`. The
intended writable BCC production profile remains supervised transaction mode;
this fallback is not a read-only substitute for the requested production end
state. No deployed configuration was changed.

Both formerly retained native regressions now pass: generic execution cannot
commit into an existing nested repository or change a canonical ref through a
hard-linked ordinary file. Ordinary canonical writes are denied without the
transaction layer; private `/tmp` Git computations still work. Direct and
nested-user/mount-namespace remount attempts cannot restore workspace writes.
Synchronous, queued, and delegated ordinary edits still publish through their
supervised transaction paths, and owner-approved commits still succeed.

Two further synthetic native tests demonstrated and fixed trusted Git path
bypasses. A hard-linked `.git/logs/HEAD` let checkout append into an unrelated
repository's ref. Staging could also obey `core.worktree=/workspace/.git` and
stage protected Git config in place of an ordinary root file named `config`.
Trusted staging/checkout now inspect metadata with the approved backend's
bounded alias/special-file/mount/layout checks and supply explicit Git-dir and
worktree paths. Existing hook/filter denials remain in place.

A final native read-only worker probe retrieved a masked synthetic `.env`
value through an ordinary hard-link alias. The development runtime's
hard-link rejection had applied only to writable launches; it now applies to
read-only launches too. Such alias layouts are refused before launch. This
test uses synthetic credentials and project secret data, not real accounts.

Process-tree cancellation fixtures formerly wrote heartbeat files directly
into the project. They now use a separate explicit test-only evidence mount,
still assert descendant termination/capacity reuse, and additionally verify the
canonical workspace stays untouched. One old worker test was updated to expect
canonical ordinary-file write denial in legacy mode. An initial full run also
correctly detected source-fingerprint drift because source was edited while
that run was in flight; final verification used frozen source.

Expanded focused native gate: **228 passed, 1 skipped**, one upstream warning.
Final full native gate with installed BCC Bubblewrap selected: **2,347 passed,
21 skipped, 24 subtests passed**, one upstream warning, in 87.05 seconds.
There are **no remaining failing tests in this run**. The unchanged skips and
warning are not provider or production acceptance passes. An intermediate
green run before the final read-only alias correction had 2,346 passes.
Compilation and `git diff --check` passed. Final log:
`/tmp/liz-bcc-full-history-alias-final.log`. Source, tests, migration procedure,
logs, and SHA256 manifest are preserved under
`artifacts/liz-bcc-no-direct-bind-20261027/`. Candidate procedure:
`docs/bcc-workspace-write-migration.md`.

The remaining work is operational and feature-completion work already needed
by the frozen contract: cross-owner projection verification, independent
signing issuer setup, scoped network Git transport, installed resource/provider
verification, immutable activation/rollback, and independent live acceptance.
The production gateway, tunnel, worker release, provider credentials, and
workspace grants remain unchanged by these candidate edits.

## Independent owner-device approval interface — candidate assets

Implemented a static owner interface in `src/agentporter/owner_approval/`.
It is not served by AgentPorter and contains no backend signing endpoint.
The owner device generates an Ed25519 key through Web Crypto with private-key
export disabled and persists the pair in IndexedDB. It exports only the public
verification key for owner-controlled BCC enrollment. Existing keys are loaded
and checked, not silently replaced; concurrent setup uses create-only storage.
The private key is never sent to AgentPorter. Actual hosting must be on an
independently trusted immutable HTTPS origin outside agent control.

The page strictly parses the complete unsigned proposal, rejects duplicate or
unexpected fields, validates supported exact commit scope, preserves 64-bit
filesystem identities with BigInt, and verifies Python-compatible canonical
JSON/domain-separated hashing. Owner details are rendered as escaped text,
never HTML. Explicit review acknowledgment and trusted signing clicks are
required; changed input invalidates review/receipt and stale async results
are discarded. Generated receipts match the backend Ed25519 protocol and
five-minute single-use claims. Push/fetch/pull proposals remain refused until
their operation-specific transport/approval support is implemented.

The browser page makes no backend requests and has no message-based signing
interface. It uses only local scripts/styles with a deny-by-default content
policy. The hosting procedure additionally requires frame-ancestor denial,
nosniff, no-store, and no-referrer headers. There are no external fonts,
libraries, analytics, or service workers. Non-exportable Web Crypto keys are
not a hardware-storage or compromised-device guarantee; independently trusted
origin/code and actual device/browser verification remain essential. Browser
storage loss requires explicit owner enrollment/rotation, not silent key reset.

Native Chrome validation used a fresh synthetic profile, normal OS sandbox,
phone-sized viewport, loopback-only static fixtures, and no existing owner
browser/account data. It proved key persistence across reload, export denial,
trusted-click versus scripted-click behavior, text rendering against injected
HTML, stale-proposal invalidation, and no outbound page requests. A receipt
generated in that actual browser successfully committed an actual staged edit
in a disposable repository through the protected Python backend. Resource
supervision in that commit fixture is a recording provider, not live cgroup
acceptance. Node/Python vectors also cover Unicode/newlines, large inode/device
integers, altered digests, duplicates, unsupported operations, and replay.

Focused gate: **67 passed**, one existing upstream warning. Full native gate:
**2,358 passed, 21 skipped, 24 subtests passed**, one upstream warning, in
87.21 seconds. JavaScript syntax, whitespace, all owner asset wheel bytes,
source/artifact manifest parity, and the isolated browser walkthrough passed.
Full log: `/tmp/liz-bcc-full-owner-issuer.log`.

Preserved source/tests/procedure/logs, screenshot, wheel, static bundle, and
SHA256 manifest: `artifacts/liz-bcc-owner-issuer-20261027/`. Procedure:
candidate `docs/bcc-owner-approval.md`. Standalone static bundle SHA256:
`0d7a31b32984dcee8110ed37dc6080381ebc629480d2f59555c234febe5c2a17`.
Wheel SHA256:
`05d4330b607519c926861e3207744313faf5c41e04da39628816d80eeb283503`.
The bundle contains no signing key or browser profile. The screenshot uses
only synthetic owner key/receipt data.

No real owner-device key was generated or enrolled, and no issuer origin,
service, protected backend policy, release, credential, or workspace grant was
installed or changed. Actual phone/browser hosting/enrollment, cross-owner
projection, scoped network Git transport, installed-resource/provider checks,
immutable rollout/rollback, and independent frozen acceptance remain pending.

## Internal scoped Git smart-HTTP wire implementation

Added `git_smart_http.py` as an internal bounded transport primitive. It is not
connected to public APIs, does not grant approval, and does not unlock push,
fetch, or pull. Protected caller code must still supply immutable remote and
credential policy, independent signatures, ancestry/object validation, resource
admission, durable remote outcome guards/recovery, and appropriate local
application before any public operation can use it.

The codec supports protocol-v0 discovery, exactly one non-deleting branch
receive-pack update, and one advertised branch's upload-pack acquisition.
It validates packet framing, service banners, unique refs, capability/object
format consistency, full object IDs, pack header/count/checksum, and exact
single-branch success reports. Discovery/acknowledgments are bounded at 8 MiB;
RPC/fetch payloads are bounded at 64 MiB including framing. These bounds and
checks are not substitutes for supervised Git object-graph validation.

The broker restricts requests to one canonical HTTPS repository and its exact
Git service endpoints, uses existing public-address-pinned TLS connections,
and ignores proxy/cookie state. It rejects redirects, wrong types, compression,
duplicate/ambiguous critical headers, and oversized/truncated bodies. Optional
raw token files require trusted ancestors, private owner modes, no aliases,
and placement outside the supplied exposed-workspace catalog. Credentials
remain in the host broker, not worker or Git subprocess environments. Remote
errors are sanitized. Failed or ambiguous publication acknowledgments and
connection cleanup produce retained outcome uncertainty; no POST is retried.

Native fixtures run actual `git-http-backend` on loopback with temporary bare
repositories, clean Git environments, and no real credentials. Only those
fixtures replace pinned public HTTPS with local HTTP. SHA1 and SHA256 tests
push a branch, reject stale discovery before POST, fetch a pack and index it
strictly in quarantine, and preserve an owner's deletion between discovery
and receive-pack. Unit tests also cover unsafe credential sources, malformed
protocol, corrupt packs, wrong-ref acknowledgment, and redirect/framing
denials. No real remote was contacted or published to.

Focused gate: **53 passed**, one upstream warning. Full native gate:
**2,390 passed, 21 skipped, 24 subtests passed**, one existing upstream warning,
in 88.92 seconds. Compilation and `git diff --check` passed. Full log:
`/tmp/liz-bcc-full-git-http.log`. Source/tests/procedure/logs/manifests are
preserved in `artifacts/liz-bcc-git-http-20261027/`, including a complete
candidate source archive and file-by-file content manifest. Procedure and
remaining integration requirements: candidate `docs/bcc-git-http-transport.md`.

The BCC worker, user gateway, and tunnel were rechecked active. A fresh
`sudo -n true` still requires owner authentication. No service, release,
credential, owner policy, project grant, or public network-Git gate changed.
The next implementation step is signed remote-operation policy/execution and
remote outcome recovery, followed by the still-required installed/live gates.


## Protected remote authority — internal candidate

Added `src/agentporter/git_remote_policy.py` and strict fixed-file
`git-remote-policy.json` loading. Authority names an exact workspace, logical
remote, canonical HTTPS repository, branch, allowed fetch/push eligibility,
credential path, fixed username, independent public verification key, and
existing single-use approval ledger. The common protected-file reader now
serves both commit and remote policies; existing commit behavior remains tested.
No public server loader or API calls this new module yet.

No wildcard/force/deletion/pull grant, duplicate tuple, inconsistent endpoint
for one remote ID, extra schema field, caller-selected authority, unsafe path,
or public/aliased policy file is accepted. Each use rechecks policy bytes,
workspace permissions and root device/inode, and the complete current workspace
catalog against policy/ledger/credential/state/package authority. A changed
policy requires an audited restart. Credentials are not read during policy
loading; the protected transport receives all current workspace roots and
validates its token at request time. The loader requires an existing ledger
and does not initialize missing authority.

Focused policy plus existing approved-commit gate: **51 passed**, one existing
upstream warning. Full native candidate gate: **2,425 passed, 21 skipped,
24 subtests passed**, one existing upstream warning, in 89.27 seconds.
`git diff --check` passed. Tests include authorization revocation after policy,
registration, root-identity, permission and workspace-catalog changes, as well
as malformed grants and unsafe policy-file fixtures. Source procedure:
candidate `docs/bcc-git-remote-policy.md`.

Preserved evidence: `artifacts/liz-bcc-remote-policy-20261027/`, including
focused/full logs, source/test/procedure snapshots, a 628-file candidate source
archive, file-by-file source hashes, and verified artifact manifest. Archive
SHA256: `91fc50d30381af6cbfe13f3362dd99a204c899e5814789f7e6e3d9413167847f`.

Worker, user gateway and tunnel were rechecked active. No service was changed,
no real remote or token was used, and no owner policy was installed. Public
network Git remains locked. Exact signed remote requests, supervised pack and
graph processing, durable publication/admission outcome recovery, authenticated
API integration, and the frozen live acceptance remain incomplete.


## Signed push and owner outcome reconciliation — internal candidate

Added `src/agentporter/git_pushes.py` and `git_push_recovery.py`. Internal
publication now uses the protected remote policy, shared synchronous capacity,
workspace mutation lease, exact independent single-use receipt, immutable
read-only pack generation, durable intent/admission binding, exact transport
acknowledgment, and durable success receipts. The request binds local repository
path/device/inode/HEAD/staged tree/branch and exact remote ID/URL/ref/old/new IDs,
pack digest/length and owner policy digest. A changed state or payload cannot
reuse the approval. No public server route or issuer UI uses this backend yet.

Fixed offline Git runs with resource supervision, read-only worktree/metadata,
a sealed clean config, no lazy fetch/replace/grafts/helpers, and only a private
pack-output mount. Complete local history is required. Existing remote tips
must be local commit ancestors of HEAD. Graph/object checking precedes bounded
sorted-object, fixed-compression packing without object/delta reuse. The broker
alone handles scoped credentials; Git never receives them. SHA1/SHA256 are
covered. No local tracking ref, commit, index or worktree data is written.

A private version-2 guard is synced before admission binding and publication.
Ambiguous outcomes never retry a POST and retain capacity/workspace blocking.
Owner-only internal recovery requires stopped worker/cgroup and exclusive
supervisor/workspace leases, verifies the exact spent claim and admission,
revalidates remote authority, and only discovers the remote ref. Fresh plans
classify current `approved_tip`, `original_tip`, or `conflict`, without claiming
whether a previous request ever ran. A changed plan or conflict cannot clear a
guard. Durable owner recovery receipts precede capacity resolution/guard
clearance. The guard-before-admission interruption is covered too.

Focused native gate: **64 passed**. Full native candidate gate:
**2,447 passed, 21 skipped, 24 subtests passed**, one existing upstream warning,
in 97.88 seconds. `git diff --check` passed. Native loopback `git-http-backend`
fixtures perform actual signed SHA1/SHA256 publication and object-integrity
checks, verify unchanged local metadata, then simulate a lost host-side result
after native publication and reconcile without a second POST. Synthetic tests
cover unauthorized/stale state, graph ancestry/graft bypass, resource loss,
remote conflict, stale owner plans, running worker, and guard tampering.
No real remote, signing key enrollment or credential was used.

Evidence: `artifacts/liz-bcc-approved-push-20261027/`, including source/tests/docs,
focused/full logs, verified artifact hashes, and complete 633-file candidate
source archive with per-file hashes. Archive SHA256: `1d283893ed16cf3fd357b66c5951cd18c9d1428505eaa6ab5cbfafcb03eb7f32`.
Procedure: candidate `docs/bcc-git-approved-push.md`.

Worker, user gateway and tunnel were rechecked active. No services, owner
policies, production files, grants or public gates were installed/changed.
Remaining work includes push-specific independent owner-device signing,
public authenticated preparation/execution, an owner maintenance entry point,
authorized fetch/quarantine/ref application, owner prerequisites, immutable
rollout and frozen independent live AP-01 through AP-06 acceptance.

## Owner-device push and authenticated push API — current candidate

The isolated candidate now extends device-side review to exact push requests.
The signer validates and displays the canonical HTTPS repository, remote
identity/ref, old/new object IDs, pack size/digest, owner-policy digest and
request digest; it rejects URL credentials, force/deletion, tags, hash-width
mismatch, malformed refs and expanded fields. Commit review remains supported.
The synthetic Chrome test signs policy-bound push requests and checks the
reviewed target fields. REST and MCP share the same protected backend. Public
client policy has an explicit `git_push` scope; `git_write` alone is denied,
owner `LOCKED` remains effective, request schemas reject caller-supplied
authority, and absent backend/policy stays locked.

The checked-in OpenAPI document was regenerated from the candidate runtime,
retaining its configured public server URL. Its full paths and component
schemas now match runtime. Focused schema/API/issuer/native push suite:
**65 passed**, one existing warning. Full native candidate suite after schema
refresh: **2,476 passed, 21 skipped, 24 subtests passed**, one existing
Starlette/AnyIO deprecation warning, in 103.27 seconds.
Full log: `/tmp/liz-ap-post-schema.log`; focused log:
`/tmp/liz-push-schema-check.log`. This verifies only the isolated candidate.

The repository checkout used for the candidate remains `/tmp/agentporter-bcc-production-XCkSZH`; these changes have not been merged into the live editable checkout or installed. The current container also cannot access the service manager or elevate: `sudo` reports `no new privileges`, and `systemctl` cannot connect to the bus. Therefore no BCC service health, process fingerprint, deployment or live acceptance result is claimed. Fetch/quarantine/ref application and pull remain incomplete. AP-01 through AP-06 remain NOT VERIFIED against the running deployment.

## Reconciled into the editable checkout

The previously isolated candidate changes have now been applied to this
editable repository. The shared-base commit delta and candidate working-tree
changes were reconciled while preserving the pre-existing local
`docs/openai-tunnel-setup.md` edit and the frozen BCC acceptance contract. All
missing untracked candidate implementation, test, and procedure files were
copied only when absent; candidate working versions of changed tracked source
and schemas were synchronized. The candidate tree itself remains intact.

Authoritative verification now runs against `/home/yeli/repos/AgentPorter`
with `PYTHONPATH` pointing at its `src/`, using the candidate's isolated Python
environment and installed BCC Bubblewrap. Full native suite: **2,476 passed,
21 skipped, 24 subtests passed**, one existing Starlette/AnyIO deprecation
warning, in 103.12 seconds. Log: `/tmp/liz-root-final.log`. `git diff --check`
passed after reconciliation. This proves editable source behavior only; the
installed service is still unchanged. Current execution environment cannot
reach systemd's bus or elevate (`sudo` is blocked by `no new privileges`). No
service process fingerprint, deployment, owner key enrollment, fetch/pull
workflow, or independent AP-01 through AP-06 live verdict is established.

## Owner review format for fetch proposals

Extended the independent browser issuer's strict proposal validator to accept
`fetch` requests. Review displays the exact canonical HTTPS origin, remote
branch and advertised object ID, computed `refs/remotes/<remote>/<branch>`
tracking target, prior tracking object, pack digest/size, owner policy digest,
and complete request digest. It rejects URL credentials/traversal, tags,
malformed refs, mismatched object formats, mismatched new/remote OIDs, wrong
tracking namespaces, invalid pack bounds and unknown fields. It never signs a
pull request. Python/JavaScript canonical signing regression suite:
**43 passed**, executed locally with synthetic keys. This is review-format
support only; there is still no fetch executor or local ref update, so fetch and
pull remain locked in the running API.

## Signed fetch integration — 2026-10-28

The editable source now has an owner-approved, per-branch fetch executor exposed
through MCP and REST when the owner remote policy is installed. The request
signature binds the exact HTTPS remote identity, remote branch and object,
tracking ref and prior tip, pack digest/size, repository state, and policy
fingerprint. The bounded Git HTTP broker obtains the pack. A supervised offline
Bubblewrap phase indexes and strictly checks the pack in a quarantine object
directory; only Git-produced pack/index files are promoted, without overwriting
existing objects. A second offline supervised phase compare-and-swaps the exact
tracking ref. It leaves `HEAD`, the index, and worktree unchanged. Fetch without
an installed authority or exact owner receipt remains denied. Pull stays
locked; fetch does not update the current branch.

A native integration test against a disposable bare Git repository passes with
the pinned BCC Bubblewrap runtime for SHA1 and SHA256. It verifies the reviewed
tracking target, object availability, unchanged `HEAD` and worktree, and owner
reconciliation after interruption both before indexing and after the ref
update. Recovery observes the exact state and clears the guard only after a
fresh owner plan hash; it never fetches, retries, deletes objects, or changes
refs. The owner-only CLI is `python -m agentporter.git_fetch_recovery`; it
requires a stopped worker and an explicit review/apply plan. The focused native
fetch/recovery tests pass (**6 passed**). Earlier fetch, push, REST/API, and
action inventory checks passed (**40 passed**), and runtime OpenAPI paths and
schemas matched (**24 passed**). `py_compile` and `git diff --check` passed.

This is source/test evidence only. No service was installed or restarted. The
immutable release, owner key/policy enrollment, phone acceptance, seven-agent
acceptance, Qman workflow, and independent AP-01 through AP-06 audit are still
incomplete or NOT VERIFIED. The earlier
2026-10-27 statement that fetch execution had not been implemented is historical
and is superseded by this section; its statement that live acceptance was not
verified remains current.

Post-integration full-suite run on 2026-10-28 completed with **2,492 passed,
21 skipped, 24 subtests passed, and one failure**: an existing fail-closed fetch
test expected the former error wording. The backend-absent behavior remained a
deny. The message was corrected to retain the established scoped-network reason;
the affected permission test, native fetch integration, and OpenAPI alignment
then passed (**13 passed**). The full suite has not yet been rerun after that
wording-only correction. Log: `/tmp/liz-current-full-suite.log`.

## Public fetch scope and final source verification — 2026-10-28

Added the distinct public-client scope `git_fetch`; `git_read` and `git_write`
do not grant network fetch invocation. The staging policy template carries the
scope, while each fetch still requires the protected remote grant and an exact
single-use owner receipt. REST and MCP tests confirm a client without the
separate scope is denied. Updated the owner-approval and Git workflow notes to
match the connected source paths and recovery support.

Latest complete native source suite: **2,498 passed, 21 skipped, 24 subtests
passed**, one existing Starlette/AnyIO deprecation warning, in 106.56 seconds.
Log: `/tmp/liz-production-full-scope.log`. Focused REST/MCP/client-scope,
commit/push, fetch/recovery, and OpenAPI checks: **46 passed**. `git diff
--check` and module compilation passed.

These results verify the editable source only. The running BCC service and its
process fingerprint remain unobserved: systemd is unreachable from this
sandbox, local/private loopback requests are blocked, and `/var/lib` staging
data is not readable here. No deployment or owner policy/key changes were made.
The owner must deploy the immutable candidate through the reviewed BCC staging
installer, then run the frozen independent AP-01 through AP-06 audit against
that running release. All six criteria remain NOT VERIFIED against BCC.

Authenticated route milestone: a disposable end-to-end test now calls fetch
preparation through REST and MCP, confirms both produce the same canonical
request, then executes the exact request via REST with its synthetic owner
receipt. It verifies the protected tracking ref advances while local `HEAD`
remains unchanged. Test passed under native Bubblewrap.

Latest complete native source suite (including that route test): **2,499
passed, 21 skipped, 24 subtests passed**, one existing Starlette/AnyIO warning,
in 126.83 seconds. Log: `/tmp/liz-production-full-api.log`. This supersedes the
prior 2,498-test run above. Deployment and AP-01–AP-06 remain NOT VERIFIED.

## Live BCC read-only observation — 2026-10-28

After reviewer-approved read-only host inspection, both `agentporter.service`
and `bcc-tunnel.service` reported active. The staging system service
`agentporter-bcc-worker.service` also reported active with zero restarts. GET
`/health` returned HTTP 200 and `{"status":"healthy"}` from both
`127.0.0.1:8765` and `127.0.0.1:8876`.

The gateway unit's `ExecStart` is
`/home/yeli/repos/AgentPorter/.venv/bin/agentporter serve`, and its working
directory is `/home/yeli/repos/AgentPorter`. Its live OpenAPI document reports
version `0.1.0` and exposes Git add, checkout, commit, and push paths; it has no
fetch path. The source's `custom_openapi` explicitly excludes `git_fetch` from
the ChatGPT Actions schema, so this omission does not establish that the REST
route or MCP tool is absent. The independent `deploy-check` below does confirm
that the gateway loaded a stale fingerprint from its editable checkout. The
configured staging worker `ExecStart`
uses `/opt/agentporter-bcc/releases/bcc-stage-20261027-05/venv/bin/python`,
while its config and working directories point into staging data version
`bcc-stage-20261027-03`. The worker returned healthy, but its live
loaded-versus-disk fingerprint was not obtained. A read-only check of the
installed release found all 1,289 files/symlinks matched its `RELEASE.json`
manifest, with package fingerprint
`955e5b48c6893e7858c67b3d0c37f3e88c922c717bffd8d18d77c88615992110`.
The worker's OpenAPI also omits `git_fetch` by the same ChatGPT Actions schema
exclusion. The manifest self-check alone did not prove loaded bytes at that
time or establish gateway/worker parity.

The documented read-only gateway `agentporter deploy-check` was run with
`--url http://127.0.0.1:8765 --expect-pid 2686385`. It confirmed the live PID
and start time, but returned `STALE`: live loaded fingerprint
`ad5279ad7e90bdd9bb44ff82eaabda7ade47f736ad19d320e268cf6b8cf86694` differs
from current on-disk fingerprint
`0603946f13b127ad6a7f04f26b2f43a118391964f67110f2bb4a316a47b730aa`. The
expected package path is the editable source directory. The systemd process
started on 2026-10-19, before the current source integration. This directly
confirms that the running gateway does not match the current source and is not
operating from an immutable release.

Acceptance impact: AP-01 and AP-02 remain NOT VERIFIED (no phone-originated
task or seven-agent identity run); AP-03 remains NOT VERIFIED because no
authorized repository workflow was executed and owner fetch authority is not
provisioned; AP-04 remains NOT VERIFIED; AP-05 remains
NOT VERIFIED because no live negative boundary tests were run. For AP-06, the
gateway's editable-checkout execution path is a concrete release-parity defect
to correct, and the worker fingerprint/recovery/rollback acceptance remains
NOT VERIFIED. The live service observations are evidence, not an independent
acceptance audit or a PASS verdict. No service, policy, release, credential,
or workspace was changed.

Before the owner restarted the tunnel, two credential-free requests to the
configured external tunnel health URL (`/health`, 15-second and 30-second
limits) timed out with zero response bytes. After the owner restarted
`bcc-tunnel.service`, both the owner's `curl` and a subsequent independent
credential-free request returned HTTP 200 with `{"status":"healthy"}`. This
establishes current external health reachability, but not the required
ChatGPT-on-phone workflow for AP-01.

A read-only `devtunnel show bcc-gateway --json` query reported the registered
tunnel ID `bcc-gateway.use`, port 8765 with protocol `auto`, and zero active
host connections (also zero client connections); a subsequent query again
reported zero host connections and a registered expiration of 26.2 days.
The registration is therefore still live; this is a disconnected host, not an
expired registration. A credential-free external
request reached the Microsoft tunnel endpoint and completed TLS, then timed
out waiting for HTTP response bytes. This is consistent with the registered
tunnel having no connected host, despite the local tunnel process reporting
`active/running`, `Result=success`, and zero systemd restarts. AP-01 remains NOT
VERIFIED because the actual phone flow was not run; the current external route
is unavailable in this observation. No alternate host or service restart was
started by the agent.

The tunnel unit's user journal had no warning/error entries in the prior 24
hours. A later `ps -p 1644330` and `/proc/1644330` inspection from the agent
environment could not see the MainPID that systemd reports. Therefore the
earlier `ss -tpn` result with no matching PID is inconclusive; the agent
execution namespace cannot inspect the host process's socket table. The
DevTunnels service's remote metadata still independently reports zero host
connections, but the local process state and cause remain unknown. Reconnecting
it requires an owner-controlled terminal action.

## Owner staging activation — 2026-10-28

The owner installed the pinned release-06 update helper and ran
`--apply --rehearse-rollback`. It reported `STAGING_UPDATED`, verified
release-05 rollback, restored release 06, and reported
`ROLLBACK_REHEARSAL_PASSED`. A second invocation of the same `--apply` correctly
refused with `Expected original staging release before apply`; the rehearsal
had already left the unit on release 06, so this was a safe precondition
refusal, not a failed rollback. Current read-only checks show the staging unit
active on `/opt/agentporter-bcc/releases/bcc-stage-20261028-06`, PID `2759341`,
zero restarts, and `/health` HTTP 200.

The current stage-06 OpenAPI document still omits `git_fetch`; source confirms
this operation is deliberately excluded from the ChatGPT Actions schema, so
that output alone is not a route test. The deployed route/tool still requires
the separately owner-provisioned `git-remote-policy.json`, verification key,
ledger, and client scope. The staging updater preserved its old configuration,
so approved fetch execution remains unverified. The production gateway remains
on its editable checkout with stale fingerprint. AP-01's external health
precondition now passes, but the phone workflow and AP-01 overall are not yet
verified; AP-02 through AP-06 remain incomplete.

Effective systemd property inspection adds partial AP-05 context. The staging
worker runs as `agentporter-bcc-worker` with `NoNewPrivileges=yes`,
`PrivateTmp=yes`, `ProtectHome=yes`, `MemoryMax=8G`, `MemorySwapMax=0`,
`CPUQuotaPerSecUSec=4s`, `TasksMax=512`, and `Delegate=yes`. Its effective unit
also reports `ProtectSystem=no`, `ProtectKernelTunables=no`,
`ProtectControlGroups=no`, `RestrictSUIDSGID=no`, and the default broad
capability bounding set. The gateway runs as the user service account with no
systemd memory/CPU limit, `NoNewPrivileges=no`, and no private `/tmp` or home
protection. These settings are observations, not proof of task isolation or
denials: the required unprivileged OS/process boundary tests have not been
performed.

The live cgroup-v2 service root reports `memory.max=8589934592`,
`memory.swap.max=0`, `cpu.max=400000 100000`, and `pids.max=512`.
`systemd-cgls` shows the delegated `supervisor` child, consistent with the
worker launcher. The parent `cgroup.procs` was empty and this auditor could not
inspect the service-owned child directory, so exact per-task cgroup placement
and limits remain NOT VERIFIED. These kernel values verify the top-level
service ceilings only.

The previously supplied runtime-gate files under
`/usr/local/libexec/agentporter/` are absent from this execution environment
(read-only `stat` returned `ENOENT`). The checkout copies are not substitutes:
their hashes are `84a53fbfcfe55668a2edda208b0990acf5fd98a6a105a73fb90cc51252e01c58`
and `9d57de9d99ea9b6e619a5542a92fecda52a4e0e0f7ab778d9272bf5380099c92`,
which differ from the supplied installed hashes. The installed
`agentporter-deploy` helper and `~/.local/share/agentporter` immutable release
directory are also absent; the service unit still points at the checkout. The
execution environment maps `/opt/agentporter-bcc` files to `nobody:nogroup`,
preventing native tests that verify root-owned Bubblewrap prerequisites; no
ownership guard was relaxed.

## Prepared isolated staging release 06 — 2026-10-28

Built a review candidate under
`artifacts/bcc-stage-20261028-06/` for the current `src/agentporter` package,
pinned to installed release 05. The 97 package files in the wheel matched the
source byte for byte; distribution metadata matches release 05. Wheel SHA256:
`c2c496ce1a5ba85fe35b0c82e645f60ee4c2a846b23e1412ef4f0f40aa2762ab`.
Expected package fingerprint:
`0603946f13b127ad6a7f04f26b2f43a118391964f67110f2bb4a316a47b730aa`.
The candidate pins release 05 manifest SHA256
`5196b89145e5c3655ccd5ff4137fdfd331682507a99070edffcbc9f9d1b585c1` and
package fingerprint
`955e5b48c6893e7858c67b3d0c37f3e88c922c717bffd8d18d77c88615992110`.

The generated owner-only update helper targets only the isolated worker
release 05 -> 06. Its pinned old systemd unit exactly matches the current
`agentporter-bcc-worker.service`; plan mode passes. The helper's wheel installer
passed a disposable install/fingerprint check, and
`tests/security/test_bcc_update_admissions.py` passed (3 tests). Artifact
`uv lock --check --offline` also passed. Hashes and limitations are recorded in
`artifacts/bcc-stage-20261028-06/CANDIDATE.md`. This update retains the existing
staging configuration; the public `git_fetch` scope and owner remote
policy/key/ledger were not inspected or provisioned, so code activation alone
will not establish a usable approved fetch path.

The candidate was not installed: the pinned root-owned BCC update helper is not
available in this execution environment. No service, staging state, credential,
or policy changed. This staging-only artifact does not update the gateway, and
AP-01 through AP-06 remain outstanding.

## OpenAI connection restored and acceptance resumed — 2026-10-28

The owner confirmed that ChatGPT's BCC connection works after recovery of the
OpenAI Secure MCP Tunnel. Host checks show `agentporter-openai-tunnel.service`
active/enabled, localhost port 18878 `/readyz` HTTP 200, gateway health HTTP 200,
and Microsoft `bcc-tunnel.service` inactive/disabled. This confirms connection
recovery; AP-01 still requires the recorded phone job/poll/result sequence.
The recovery used the existing OpenAI tunnel ID; credentials are not recorded
in this report. The client doctor probes did not apply MCP authentication;
runtime readiness and the actual ChatGPT call were used instead.

Read-only authenticated MCP inventory is recorded in ignored local evidence
`artifacts/bcc-acceptance-current/inventory.json`. It confirms the gateway still
runs PID 2686385 from the editable checkout and advertises host-credential
workers. The separate isolated worker remains release 06, PID 2759341. Thus
worker staging activation is complete, superseding the older candidate-not-
installed statement above; production gateway migration remains outstanding.

Candidate validation against BCC's configured
`AGENTPORTER_TEST_BWRAP=/opt/agentporter-bcc/bin/bwrap` passed 22 confinement,
readiness and update checks; 199 relay/provider/runtime checks (one skipped);
and 98 approved Git/transaction/recovery checks. These are candidate checks,
not independent live acceptance. The first runtime invocation used the OS
Bubblewrap 0.6.1 and failed 13 checks for unsupported `--disable-userns`;
selecting the actual installed sandbox corrected the validation target.

The old cross-owner idmap probe pinned the incorrect owner UID/GID 1000:1000.
A new copy pins the verified BCC identities 2056259175:2056259276 and 997:997,
retaining all other guards. File:
`artifacts/bcc-openai-recovery/bcc-idmap-probe-current.py`, SHA256
`26ce1298848d1886ea2613403aab1aff9aeab4ddadd457c455101e936f06211f`.
It compiles; privileged execution is pending owner sudo authentication.
No gateway cutover or real-project worker enrollment has been performed.

The broader unit/security run completed with 2,472 passed, 21 skipped and 24
subtests passed; one isolated-Python packaging check failed because the
separate validation virtualenv had no installed AgentPorter distribution.
Installed the existing stage-06 candidate wheel into that disposable virtualenv
only and reran the affected `test_isolated_codex.py` module: 21 passed. The
running gateway environment was not changed. Full baseline output remains in
`artifacts/bcc-acceptance-current/candidate-validation.log`; the initial failed
run is retained rather than overwritten. The corrected module's result does
not represent a second full-suite run. The privileged idmap probe and live
AP-01 through AP-06 audit remain outstanding.

Owner execution exposed two errors in the diagnostic itself: permission mask
06222 rejected root-owner write on the valid 0755 sandbox (corrected to runtime
mask 06022), then the mount mapping mapped worker -> owner rather than on-disk
owner -> worker. The latter produced overflow UID 65534 at the projection check,
before launching the synthetic write. Temporary probe directories are absent
after cleanup. The corrected mapping follows mount_setattr(2)'s source-to-target
mount ID semantics. Current probe SHA256:
`c6604f93e4ccf8009035d5210121ceeffd6043f70ef2d4021a2f1c1278c937ab`.
It compiles; privileged successful execution remains NOT VERIFIED. These
failures do not establish that kernel idmapped ownership is unsupported.

## Owner cross-owner idmapped-overlay probe PASS — 2026-10-28

Owner reran the corrected root-installed diagnostic and supplied:
`exit_code=0`, `private_upper_verified=true`, `projected_uid=997`,
`source_uid=2056259175`, `source_unchanged=true`, empty stderr, `worker_uid=997`.
Current diagnostic SHA256 is
`bb9fd30855fa5210a53f3bdc23aa59b27ef449f0f2448a847e54ae0db8bf608f`.
The preceding failed output was superseded by this successful second run.

The diagnostic now explicitly uses `--unshare-user` alongside `--unshare-all`,
matching the production runtime, and writes the exact synthetic newline through
Python repr. The launch flags and private-write verification were independently
executed against disposable same-owner files before the owner privileged run.
The successful privileged run demonstrates BCC kernel support for read-only
idmapped lower mounts and isolated worker overlay copy-up while preserving the
canonical README. It does not yet establish persistent projection provisioning,
real-project enrollment, controlled publication, or full AP-05 acceptance.

Authenticated live MCP inspection of isolated release 06 reports all seven
named agents (`jax`, `liz`, `prof`, `phil`, `wei`, `ming`, `argie`) with
`runtime_delegatable=true` and `confinement_status=verified_development_bwrap`.
Evidence: `artifacts/bcc-acceptance-current/staging-inventory.json`. This is
executable/confinement readiness, not a provider job or ChatGPT AP-02 PASS.
Live staging MCP `exec_run` then deliberately exited 7 with the expected marker
and accurate returned status; a subsequent execution exited 0 with
`BCC_CLEAN_SUCCESSOR`, empty stderr, no truncation or timeout. Evidence:
`artifacts/bcc-acceptance-current/staging-live-checks.json`. This contributes
staging failure/recovery evidence to AP-06; it is not the final production audit.

## Mapped-lower integration candidate, release 07 — 2026-10-28

Added `sandbox/workspace_projections.py` and transaction integration: foreign-
owned writable workspaces require an owner-provisioned read-only view at a
fixed protected path keyed by source device/inode. Every parent is opened
without symlink following and checked root-owned/nonwritable by group/other;
source inode, mapped worker UID/GID and read-only status are verified. The
lower descriptor is pinned and closed with the transaction, while baseline,
locking, conflict detection and publication retain the canonical descriptor.

Prepared a standard-library-only owner provisioning helper,
`scripts/bcc-workspace-projection.py`, with plan-only default, canonical source
constraints, fixed BCC identities, pinned-source mount cloning and root-only
apply from an installed trusted path. It does not enroll workspaces or grant
ACLs. Its privileged apply is not yet verified. Foreign-workspace views are
fail-closed after reboot until owner reprovisioning.

Release 07 artifacts and exact hashes are in
`artifacts/bcc-stage-20261028-07/CANDIDATE.md`. Full unit/security baseline:
2,483 passed, 21 skipped, 24 subtests passed. Provisioner checks separately:
3 passed. Disposable updater installation matched the pinned new fingerprint.
No staging activation or gateway cutover has occurred for this candidate.

## Release-07 activation verified; ownership-preserving publication candidate

Owner activation reported update -> release-06 rollback -> release-07 update,
with `ROLLBACK_REHEARSAL_PASSED`. Read-only host verification confirms staging
PID 2866696 runs release 07 and health returns HTTP 200. OpenAI tunnel readiness
continues HTTP 200. Production gateway remains on its existing process.

Pre-enrollment review found that atomic canonical replacement under worker UID
could change host ownership and remove the owner's ordinary in-place write
permission. Source candidate now separates a read-only mapped lower view from
a writable mapped publication view accessible only to the trusted publisher.
Both require protected root-owned parents, matching source inode, mapped
worker identity and the exact intended mount access mode. The publication FD
is never included in job pass_fds. Transaction publication and offline recovery
use the mapped publication descriptor to preserve underlying host ownership.
These latest source changes are not installed in release 07.

Focused projection/transaction/recovery/helper checks: 59 passed; additional
publisher-mode, FD inheritance and failure-cleanup checks: 25 passed. Prepared
private synthetic ownership diagnostic:
`artifacts/bcc-openai-recovery/bcc-publication-owner-probe.py`, SHA256
`58e29b01484236fa2939224497e8449b3c2cd95113ff561def492ea1ae0e865f`.
It creates temporary synthetic owner files, privately mounts a mapped publisher
view, drops to worker identity, replaces a synthetic file, and checks raw owner
UID/GID and content. It compiles and its non-root refusal was exercised before
mutation. Privileged result remains NOT VERIFIED; no real project is enrolled.

Owner publication probe verified `exit_code=0`, expected publication content,
and canonical owner UID/GID 2056259175:2056259276. The ownership behavior passes.
Subsequent private-mount cleanup failed EBUSY because the cloned mount FD was
still retained during a normal unmount. The process exited; host findmnt shows
no surviving probe mount. One synthetic root-owned temporary directory remains:
`/var/tmp/bcc-publisher-proof-t5xusk06`. Cleanup must be completed during the next
owner step. The probe now closes its cloned mount FD first and uses private
lazy detach, matching the earlier successful overlay probe. The corrected
cleanup is compiled but its privileged execution is not yet verified.

Prepared release 08 with mapped trusted publication and recovery. Exact pins
and validation coverage are in
`artifacts/bcc-stage-20261028-08/CANDIDATE.md`. Full baseline: 2,489 passed,
21 skipped, 24 subtests passed; subsequent recovery-directory descriptor fix:
25 affected checks passed. Final updater installation fingerprint verified in
a disposable baseline copy. The corrected owner probe additionally validates
and removes the exact stale synthetic directory before testing, and closes
the cloned mount FD before private lazy detach. Its current SHA256 is
`532c3b3eeec6a15cf538d9026279456f7e5688e4dc865fedb2a7c1999e8fbde7`.
No release-08 activation, project enrollment, or gateway cutover has occurred.

## Release-08 activation and ownership cleanup verified

Owner reports update -> rollback -> update with ROLLBACK_REHEARSAL_PASSED.
Host checks confirm staging PID 3086969 runs release 08 and health is HTTP 200;
OpenAI readiness remains HTTP 200. The corrected ownership probe passed and
removed its prior synthetic directory. Host listing finds no remaining
`/var/tmp/bcc-publisher-proof-*` directories. Prepared a disposable owner-owned
fixture and worker-only installed-package integration check under
`artifacts/bcc-acceptance-current/`. Persistent mapped views and real-project
enrollment remain unprovisioned; the production gateway remains unchanged.

## Installed cross-owner transaction PASS; bounded fixture enrollment prepared

Owner provisioned read-only lower and writable publication views and ran the
release-08 integration check as UID/GID 997. It reported
`cross_owner_transaction=PASS`, `canonical_owner_preserved=true`, publication
FD excluded from job inheritance, and `cleanup=PASS`. Independent host
inspection confirms the output is `BCC_OWNER_PUBLISHED`, owner
2056259175:2056259276, mode 0644; findmnt reports distinct `ro` and `rw`
`nosuid,nodev,idmapped` views. These views are provisioned for the disposable
fixture only; they are not real-project enrollment or final AP acceptance.

Prepared `scripts/enroll-bcc-acceptance-fixture.py` (SHA256
`bc4eee7d00c277abc97da1623629324c662a177bbe09f4d992916e9a5e6fc47f`).
The root-installed owner helper adds only `bcc-owner-fixture`, pointing at the
mapped publication view, and enables workspace transactions on staging. It
preserves the existing workspace, worker credentials and provider definitions;
it does not grant commit/push or change the production gateway/OpenAI tunnel.
It uses the already-reviewed SQLite admission barriers, root-private backups,
pinned no-follow configuration directories, strict duplicate/alias-free YAML,
health-checked restart and failure rollback, plus explicit rollback/recovery.
Ten focused helper/admission checks passed. Its privileged application is
pending; it has not restarted a service.

Planned public-path migration: after scoped worker API and provider validation,
retarget the existing OpenAI tunnel to the immutable isolated service on 8876
with its scoped key. This keeps file operations and delegated jobs in one
service/transaction policy. Existing legacy gateway integrations are retained
until separately reviewed. This migration has not been performed.

## Live fixture API/security/recovery and provider results — 2026-10-28

After owner fixture enrollment, live MCP read/write and transactional exec
succeeded, retained institutional owner UID/GID on both direct API and job-created
files, accurately returned deliberate exit 7 and a clean successor exit 0.
REST returned 200 for scoped read, 403 for unrelated workspace, 400 for traversal,
and 403 for unapproved commit/push. A safe confined command could not open host
secrets, service/config write handles or host loopback. Evidence is in local
`artifacts/bcc-acceptance-current/fixture-api-checks.json` and
`rest-os-boundary-checks.json`. No protected file contents were read or written.

Actual provider-backed read-only jobs: Liz job_e7e39d3a650844c89ab356c0 and Prof
job_f0f788d0eefa4f678267559b completed with the correct ordinary-file hash and
identity markers. Reported actual backend model remains unknown; configured
model evidence is kept separately and is not promoted to actual backend proof.
Jax job_37df6bad9f2047ffa1e7986c failed connection retries; captured CLI metadata
confirms provider=headroom. The owner route points to loopback and is unreachable
from the isolated network. Ming job_3368534025934147ad40ecfb failed expired OAuth;
Phil job_cf1c13f4b4194a1882545794 rejected credentials; Argie
job_72fef736a46b4523b135a331 returned provider HTTP 403. No alternate agent/model
was substituted. These local provider checks are not final phone AP-02 PASS.

A further Liz delegated check got EROFS opening the existing fixture for writing;
host secret and service paths were absent in its namespace (ENOENT), which is
path nonvisibility, not a separate filesystem ACL verdict. Exact trace retained
in `liz-readonly-boundary-check.jsonl`. Deliberate asynchronous failure
job_7fdd34f0f5784322b8abf5ac reached failed/exit 7, retained its marker in job_result,
and a clean subsequent execution succeeded. Evidence:
`async-failure-recovery.jsonl`. AP-05/AP-06 still require final independent audit.

Prepared release 09 and a BCC-specific owner credential synchronization helper;
full current unit/security run: 2,500 passed, 23 skipped, 24 subtests passed.
Pins, scope, route repair and cost-guard evidence:
`artifacts/bcc-stage-20261028-09/CANDIDATE.md`. Provider authentication and Jax's
explicit same-account route correction remain owner-controlled; source sessions
may still need native re-login if the owner's copy is itself expired. The
existing production gateway and working OpenAI connection have not been changed.

## Release-09 verified; provider retry and release-10 candidate

Owner credential synchronization refreshed Ming/Argie, retained current Phil/Wei
credentials, and explicitly repaired only Jax's confined Headroom route to its
existing ChatGPT OAuth account on direct OpenAI. Owner release-09 update/rollback
passed; host shows release 09 PID 3149072 and OpenAI readiness remains HTTP 200.

Retried read-only provider jobs: Ming job_53db95caf1de4958aaf886d3 completed with
correct ordinary-file content/hash. Jax job_7bfd1ee77b364bc88cf3b59e failed workspace
routing discovery; inspection found the code still assigned an empty direct
provider ruleset to Jax, an implementation mismatch with the explicit route
repair. Phil job_6d866c8f7a7c43cbace1ecd2 still rejected credentials; Argie
job_94e9a188bc6747bc9818d80b returned empty HTTP 403; Wei
job_380f878a75aa4b71b7ccb12e returned an unexpected server error. No alternate
agent/model was substituted, and no permission was widened to mask a failure.

Prepared release 10: narrow Jax direct provider operations, explicit documented
Wei inference endpoint/model configuration, and secret-free structured broker
vs upstream failure diagnostics. Candidate pins/coverage are in
`artifacts/bcc-stage-20261028-10/CANDIDATE.md`. Full baseline 2,506 passed,
23 skipped, 24 subtests passed; after final log formatting correction, 87 broker
checks passed. Privileged activation and live retest pending. Current provider
failures remain unresolved until actual successful executions are recorded.

Owner-device approval hosting preflight: BCC's Tailscale Serve configuration is
empty, its private DNS is bcc.tail7d013a.ts.net, and an iOS peer is online. A
separate root-sealed, static approval origin on the existing tailnet is a
possible independently protected owner-device issuer path; none has been
installed or exposed, and no signing key has been created on the owner's device.

Release 10 activated with successful new -> original -> new rollback rehearsal.
Jax live job `job_7ca1b08e91724ce8a098d8f7` completed successfully with the expected
fixture hash/marker. Phil `job_ea601d31a2be411aa0ae0a3e` still rejected authorization;
Argie `job_b17d886bef2e460e9be5536e` still returned HTTP 403. Wei
`job_5a98a3984b5c4d648113a8df` produced no result and reached the enforced 900-second
timeout, recorded exit 124. No alternative paid model was selected.

The attempted public Wei cancellation exposed a missing client policy rule.
Source now permits cancellation only for ledger-recorded public jobs whose
workspace retains execution or dispatch scope; unrelated IDs and read-only
scopes remain denied. Cancellation/lifecycle/process checks passed (28 checks;
the combined 44-check run had only an unrelated static-host test setup failure).
This policy fix is not installed yet. Prepared a stdin-only diagnostic filter
that exposes only allowlisted provider labels/status codes; two tests verify
private values and arbitrary fields cannot pass through. Reading the worker's
protected log still requires the owner's sudo action. Production acceptance
remains incomplete; the existing working OpenAI tunnel has not been retargeted.

Owner-provided sanitized release-10 diagnostics establish Wei's upstream HTTP
429 responses on the admitted free inference route. Phil's model request
POST /v1/messages on api.business.githubcopilot.com was denied by operation
scope. GitHub's Copilot SDK reference documents that exact model endpoint.
Release-11 candidate admits it on the existing four Copilot origins and applies
Anthropic-style local-tool validation there; hosted search/remote connectors
remain denied. Tests cover all four origins and hosted-tool rejection.

Argie's streamGenerateContent failed during request-header/body collection,
before payload validation or upstream forwarding. Existing diagnostic ValueError
was too coarse to identify the failing framing invariant. Candidate 11 maps
known parser failures to fixed nonsecret categories; it does not relax framing,
HTTP authority, operation scope, or payload inspection. Candidate 11 also includes
the tested public-job cancellation fix. Owner activation and actual provider
retests remain necessary. Existing staging and OpenAI readiness are healthy.

Release-11 full source validation completed: 2,528 passed, 23 skipped, 24
subtests passed. Exact-updater disposable wheel installation matched the pinned
package fingerprint. Candidate/source bytes match; owner activation pending.

Release 11 activated with owner-reported successful rollback rehearsal; live
system unit ExecStart resolves to release11, PID3309359. Phil provider job
job_1c2d3c9849b1464b89ea115f completed exit0 in8.69s, returning the expected
ordinary fixture text, SHA2566f09ea5c4badba8bc1c9cbaec23312eed1e36fdca6d14229507979e98404874c,
and BCC_PHIL_PROVIDER_OK. Backend model remains honestly unknown.
Argie job_56aea47cd0224b7c9c88277b still failed exit3/empty403; new fixed-label
parser diagnostics require owner read from protected log.
Public exec cancellation job_894095997ff7478f981f8fe6 reached cancelled/exit130;
a clean successor exited0 with BCC_CANCEL_CLEAN_SUCCESSOR. Exact job evidence
saved in artifacts/bcc-acceptance-current/public-cancellation-release11.jsonl.
This verifies live cancellation routing/cleanup, not independent final acceptance.

Owner-provided release-11 sanitized diagnostics identify Argie's generation
request failing with body_framing. Prepared release12 strict bounded chunked
POST decoding: disallow Content-Length/Transfer-Encoding combinations,
non-chunked codings, Expect, trailers/extensions and malformed chunks; decode
before inspecting JSON/local tool declarations; canonical Content-Length only
upstream.16MiB decoded limit,4096chunks maximum,total deadline. No new network
origin/operation/credential authority. Focused broker baseline109passed before
three additional deadline/boundary tests; full final suite pending. Exact
updater disposable install verified against pinned package fingerprint.
A single same-model free Wei retry was dispatched as
job_ed5ca71fa7214d2f9a6b7678; bounded120s observer cancels if no terminal result.

Release12 final full validation: 2,551 passed,23skipped,24subtests passed
in112.81seconds. Exact-updater disposable installation matched candidate
fingerprint267e5c654ef86ffe1afddfe6d0f38bee4f03768850845fb8aa047514e6aea8d6.
Owner activation and live Argie compatibility remain pending.

Wei retry job_ed5ca71fa7214d2f9a6b7678 produced no result within120seconds.
Public cancellation succeeded; independent status/output reconciliation records
cancelled,exit130,duration121.02seconds,empty stdout and only model startup banner.
No job remains running from this retry and no alternate model was used. Isolated
installed release12 wheel import/fingerprint validation also passed. Owner may
now activate candidate12; live Argie behavior is not yet verified.

## Release 12 Argie retest — 2026-10-28

The owner reported release 12 activation and rollback rehearsal succeeded.
The first Argie fixture job, `job_a3ddb9f933c2494092ed6714`, exited 0 but
returned no answer: the CLI reported that a command permission was denied.
That is not a successful fixture check. A subsequent read-only job,
`job_34b0b1baa3dc48508fe86a8c`, explicitly requested the file-reading tool
without a shell. It completed with exit 0, returned `BCC_OWNER_PUBLISHED` and
`BCC_ARGIE_PROVIDER_OK`, and had empty stderr. Evidence is in
`artifacts/bcc-acceptance-current/argie-read-tool-retry.jsonl`. The API reports
actual model as unknown, and this staging check is not the independent
phone-originated AP-02 acceptance test.

Read-only systemd inspection found the production gateway still running from
the editable checkout, PID 2686385. Thus audited immutable production release
parity remains unverified; staging activation is not production deployment.

## Production gateway preflight — 2026-10-28

The OpenAI Secure MCP Tunnel service was active and its `/readyz` endpoint
returned `ready`. The production gateway deploy check reported `STALE`: PID
2686385 loaded fingerprint `ad5279ad7e90bdd9bb44ff82eaabda7ade47f736ad19d320e268cf6b8cf86694`,
whereas the current source fingerprint was
`267e5c654ef86ffe1afddfe6d0f38bee4f03768850845fb8aa047514e6aea8d6`.
The gateway still runs from the editable checkout. The isolated staging worker
was running release 12; its successful activation does not update the gateway.

The current production delegation relay explicitly rejects writable dispatch;
the separately tested writable public worker path does not establish a safe
production-to-worker write path. Focused relay and writable-delegation tests
passed on BCC outside the sandbox: 43 passed. The same tests failed inside the
sandbox because mapped ownership made trusted root-owned ancestors appear
untrusted. These tests do not validate a production cutover or writable relay.
Phil's release-12 fixture job `job_993de8bd7f9a473f9d483581` completed with the
expected fixture, SHA256 and marker; the API reported its actual model unknown.
Wei's later bounded retry `job_5a669bcee4124831a0218989` produced no answer and
was cancelled and reconciled as terminal exit 130. The owner requested Phil for
the immediate live test; frozen AP-02 still names Wei separately.

## Transaction and Git candidate recheck — 2026-10-28

The production configuration directory has neither a delegation relay key nor
an upstream allowlist; the isolated staging worker is not connected to the
production gateway by this relay. A BCC host run against the current candidate
with the installed Bubblewrap tested agent workspace transactions, workspace
recovery, approved fetch, approved commit, and native approved push: 43 passed.
These are local component tests, not proof of an installed production path or
of AP-03. An explicit writable production delegation design and independently
reviewed immutable cutover remain necessary.

## Gateway candidate copy — 2026-10-28

Prepared `artifacts/bcc-gateway-candidate-20261028-12/venv` as a review copy
of the installed staging release 12 environment. A file-by-file SHA256 and
symlink comparison found all 1,304 non-cache entries identical to the staging
environment. Its AgentPorter package fingerprint is
`267e5c654ef86ffe1afddfe6d0f38bee4f03768850845fb8aa047514e6aea8d6`;
the source wheel digest is
`27fa9dab789ecf87ff4deb90ed6ffaef23a8ed5cc5ddbdfc44c19326cb652461`.
`REVIEW-MANIFEST.json` SHA256 is
`09df36b2ccfe355afb1966258e88621f93a78f7595aff3ab31e3d1cec146a7b5`.
Isolated Python imported the gateway, relay, transaction, and approved Git
modules from this copy, and the CLI help command succeeded. This copy is in an
agent-writable workspace: it is not an immutable production install, has not
been reviewed for gateway compatibility or activation, and does not provide
the missing worker routing. No service or OpenAI tunnel was changed.

The candidate was subsequently started as an in-process ASGI application
with disposable configuration using the candidate's isolated Python. Its
health endpoint returned 200, unauthenticated REST returned 401,
authenticated REST workspace listing returned 200, and an initialized
authenticated MCP tools/list request returned 200 with `list_workspaces`.
The reproducible smoke script is `artifacts/bcc-gateway-candidate-20261028-12/gateway-smoke.py`.
The first probe used a missing trailing slash for REST and omitted MCP
initialization; after correcting those test requests the checks passed.
This is a disposable application test, not a production configuration,
process, tunnel, relay, or acceptance test.

## Relay public-client policy guard — 2026-10-28

Source now refuses to start the production delegation relay when no explicit
public-client policy exists. Previously the upstream relay could be configured
while the legacy unscoped public-client mode remained active. The guard leaves
the no-relay legacy profile unchanged and does not enable the relay or grant
write authority. The production relay and public-delegation focused tests
passed on BCC: 45 passed, including missing-policy and dedicated-key startup regressions.
This change is source-only; release 12 and the review copy predate it and must
not be represented as containing it. Production activation and full validation
remain outstanding.

## Writable production relay source candidate — 2026-10-29

The source has an opt-in writable delegation path, disabled by default. The
gateway and receiving worker each require their own private
`delegation-relay-write-scope.yaml` mapping, with paths matching the existing
relay scope. The production gateway additionally requires the explicit public
`dispatch`, `write`, and `dispatch_write` grants and a writable workspace. The
worker refuses writable relay startup without supervised workspace transactions
and a matching writable registry entry; the gateway requires a positive worker
handshake before launching a writable job. Commit and push remain denied by the
relay. The existing read-only relay remains the default.

Source validation on BCC: 155 focused tests passed and one skipped; the full
suite passed 2,583 tests with 23 skips and 24 subtests passed. The existing
offline relay protocol regression script passed. An assembled relay test checks
startup refusal without transactions, the explicit handshake, denial of push,
and a mocked writable dispatch. These are not an end-to-end real worker
publication test or an independent security review. This code is not installed,
and release 12 and the gateway review copy predate it. Production remains
unverified and the OpenAI tunnel and live services were not changed.

The production relay client and receiving HTTP route were subsequently
exercised together with a native synthetic Bubblewrap worker and real workspace
transaction finalization on BCC. A successful job published its fixture edit;
a job exiting 7 left the fixture unchanged. The six native agent-transaction
tests passed. This test bridges the two services in-process, stubs provider
egress admission, and uses synthetic credentials and a recording resource
supervisor: it does not prove live provider access, TCP isolation, kernel
cgroup limits, or deployed end-to-end behavior.

## Staging candidate 13 — 2026-10-29

Prepared `artifacts/bcc-stage-20261029-13/` from the current source and the
installed release 12 baseline. The wheel SHA256 is
`fbdf2063e628363c32e494b9fc24581e930915dea313bb81c0a29ad643f2db06`, the
package fingerprint is
`fd7d46156f9d79df0ca319e808c2ccd40dec9c2592a66a8000f81a82f63de3a4`, and the
updater SHA256 is
`409cd8e265738af78e8c3f2d742cafffaabd1fcb6b9a29eb4423bb7d934d2f16`.
The updater plan names release 12 as its baseline. Its actual wheel installation
function ran on a disposable copy and produced the pinned fingerprint. The
candidate is not installed or independently reviewed, and its update does not
install writable relay policy or verify production behavior. Do not treat the
candidate as live acceptance evidence.

Candidate 13 was also installed into a disposable review virtualenv and its
package fingerprint matched the pin. The same disposable ASGI smoke used for
release 12 passed health, unauthenticated REST denial, authenticated REST,
and initialized authenticated MCP tool listing. The staging service remained
on release 12. Host `sudo -n -l` showed no passwordless authorization for the
staging updater; therefore this check did not install or activate candidate 13.

The candidate-13 wheel's installed package was then loaded from its review
virtualenv for the relay, development runtime, native agent transactions,
public delegation and writable delegation tests: 161 passed, one skipped, with
one Starlette/AnyIO deprecation warning. The harness asserts the AgentPorter
package path before running pytest. The test suite and pytest runtime are from
the checkout/test virtualenv, so this is packaged-code component validation,
not installed-service or independent production acceptance evidence. Harness:
`artifacts/bcc-stage-20261029-13/verify-packaged-relay.py`.

An attempt to install the exact candidate-13 staging helper through the
approved host command failed before installation: `sudo: a password is
required`. The helper has not been installed by that attempt and no staging
service was changed. Owner authentication or a narrowly scoped privileged
installation path is needed for the staging update; the review and live relay
checks remain separate outstanding gates.

## Current owner approval bundle — 2026-10-29

The earlier October 27 approval bundle no longer matches the current source:
its HTML, application and protocol assets differ. Prepared the current four
assets in `artifacts/bcc-owner-approval-candidate-20261029/` and verified each
byte against the candidate-13 wheel. The asset manifest SHA256 is
`802a314bfeadc0fd0908edbd6740034c8c53cc39871c964a6459df0db779c27e`.
The owner-approval browser, protocol and host tests passed on BCC: 61 passed,
including synthetic browser signing of a disposable commit and push. This
bundle is agent-writable and is not a trusted issuer installation. The owner's
independent HTTPS origin, real phone key enrollment, live policy and actual
signed repository workflow remain unverified.

Read-only BCC preflight found Tailscale Serve configuration `{}`, the local
Tailscale DNS name matching the approval host's configured name, and no TCP
listeners on proposed ports 8443 or 18879. Prepared a draft DynamicUser systemd
unit in the approval candidate directory (SHA256
`5e2370d97f9a02666201e48dbfa934d567917a2f60cd774147a67e48aa6b0098`).
`systemd-analyze verify` returned zero but emitted warnings for unrelated host
units; no instance was started. The host script SHA256 is
`a9fb46a5064706a9e25c34c5d5950635532001cdb26ff8610e073d0b91fb3666`.
Root-owned asset and script installation, service isolation, Tailscale HTTPS
access and the owner's phone key enrollment remain unverified; this draft and
the empty Serve configuration do not establish an independent trusted origin.

The Tailscale status subsequently listed `bcc.tail7d013a.ts.net` in
`CertDomains` with backend running and no health warnings. This is a read-only
capability observation, not proof that the owner phone can reach the proposed
HTTPS origin.

The current production gateway reports `Delegate=no` in systemd and runs in
`.../agentporter.service`, whereas `JobResources` and the supervisor bootstrap
currently accept only the isolated worker/development service cgroup names.
Moreover the gateway constructs job resources only from development runtime
settings. Thus the existing production gateway cannot simply enable supervised
workspace transactions: it needs a reviewed production resource profile and
delegated cgroup setup before that mode can start. The successful isolated
worker transaction tests do not establish this gateway capability. No live
configuration was changed.

## BCC gateway resource profile candidate — 2026-10-29

Source now supports a separate private `gateway-job-resources.yaml` profile
for a BCC production gateway, with a dedicated
`agentporter-bcc-gateway.service/supervisor` cgroup requirement. It refuses a
combined gateway/worker profile and refuses gateway budgets without an explicit
public-client policy. The supervisor selects the gateway loopback port 8765 for
that service; worker services retain port 8876. The existing job resource
limits, exclusive supervisor checks, cleanup and transaction paths are reused.

On BCC, 50 focused resource, relay and native transaction tests passed after
the final policy guard. Before that final guard, the full suite passed 2,589
tests with 23 skips and 24 subtests. Cgroup bootstrap was tested using simulated
kernel membership; no production gateway unit, actual delegated cgroup,
protected profile, release or live service has been installed or verified.
Candidate 13 predates these source changes and must not be treated as including
the gateway resource profile. Independent security review and an actual BCC
systemd/cgroup staging test remain required.

The gateway budget-file loader was subsequently hardened to reject hard-linked
control files and to compare descriptor metadata and byte count before and
after reading, failing closed on a concurrent change. The focused gateway,
supervisor, relay and transaction suite passed 51 tests after this change,
including hard-link and mid-read mutation cases. Candidate 14 predates this
source change; it must be rebuilt before this hardening can be deployed. The
full suite was not rerun after this specific change.

The complete suite was rerun after the final gateway policy guard: 2,589
passed, 23 skipped, 24 subtests passed. Prepared staging candidate 14 from this
source and the still-running release 12 baseline. Its wheel SHA256 is
`c08df1a6a1551f5e6130f4999ee790d5578084a43a96c0cc6c07d9fd60da0146`, package
fingerprint `921e9aee074655807efa86464cf5f13cb717e56a351b14b0e836d1d76eb6ca9a`,
and updater SHA256
`81ae11b6c6cd7503f4b761ee0925b8a6123be7b7ab943569e6e1819b39887041`.
The updater's wheel-install function produced the expected fingerprint in a
disposable copy. Candidate 14 is not installed, independently reviewed or
validated as an actual gateway cgroup deployment.

Candidate 14's installed package was loaded from its separate probe virtualenv
for the gateway resource, supervisor, relay, worker runtime and transaction
checks: 188 passed, one skipped, with one Starlette/AnyIO deprecation warning.
The harness asserts the package path. This remains packaged-code validation;
tests use the checkout and a test virtualenv and do not establish the actual
system-service cgroup or installed production behavior.

Candidate 14's packaged Git backend and the synthetic owner-browser tests
subsequently passed 72 tests, with one Starlette/AnyIO deprecation warning.
The fetch API test exercises an MCP proposal and an exact signed REST
execution against a local synthetic Git transport. A separate disposable MCP
discovery check parsed the returned tool list and found the exact names
`git_fetch`, `git_commit`, and `git_push`. These checks do not establish
OpenAI-tunnel delivery, owner phone signing, remote network publication, or
live AP-03. Reproducible harnesses are in the candidate-14 artifact directory.

## Live gateway cgroup probe — 2026-10-29

A disposable, collected user-systemd unit named
`agentporter-bcc-gateway.service` ran candidate 14's isolated Python with
`resource_supervisor --probe` and `Delegate=yes`. It exited without starting a
gateway: `CPU/memory/pids delegation is required`. The user manager's cgroup
lists only `memory pids` in both `cgroup.controllers` and
`cgroup.subtree_control`; CPU is unavailable to that manager. After the probe,
the transient unit was confirmed not found and inactive. This is a real host
constraint, not a passing resource test. A separately reviewed system-service
arrangement or owner-controlled controller delegation is needed before testing
the gateway profile; neither was installed. The existing gateway and OpenAI
tunnel were not restarted.

Parent inspection shows CPU available at `user.slice` but not enabled in its
`cgroup.subtree_control`, which contains only memory and pids. Enabling it is
a host-wide systemd policy change; it was not attempted. A system-service
alternative also requires a privileged, separately verified deployment.

The system unit name `agentporter-bcc-gateway.service` was verified not found
and inactive. A proposed collected transient systemd `--probe` would execute
the candidate-14 supervisor as the unprivileged `yeli` account, without
starting the gateway or opening a port. A host-side `sudo -n systemd-run` attempt
failed before launch with `sudo: a password is required`; no transient system
unit was created by that attempt. A human-authenticated system probe is still
needed to determine whether the system-service arrangement has the required
controllers. The existing gateway and OpenAI tunnel remain unchanged.

Draft system gateway and OpenAI tunnel unit candidates are in
`artifacts/bcc-gateway-cutover-candidate-20261029/`. The tunnel candidate
differs from the installed unit only by removing its user-service dependency
on the old editable gateway; it preserves the OpenAI tunnel command and
environment references. The actual gateway draft fails `systemd-analyze
verify` because its intended immutable `/opt/agentporter-bcc/gateway-current`
Python does not exist. Replacing that path in a temporary syntax-only copy
with `/usr/bin/python3` gave a zero exit, alongside unrelated host-unit
warnings. This is not validation of the intended binary, a runnable cutover,
system-service delegation, rollback, or the tunnel's behavior after cutover.
Neither unit is installed. The system-service probe output remains unverified.

Read-only registry inspection found `/home/yeli/repos/Qman` present and its Git
worktree clean on `main`, but neither `Qman` nor `qman` is registered as a
distinct production workspace. The existing registry instead includes a
writable `/home/yeli/repos` parent as well as writable AgentPorter and obsidian
entries. Those legacy registrations do not establish safe Qman delegation or
authorize a blanket production policy. A reviewed Qman-specific mapping and
protected-project handling are required before the frozen live Qman test.
No project or registration was changed.

Read-only execution of the draft BCC discovery classifier found 33 eligible
top-level entries including Qman and excluded AgentPorter and obsidian. A
synthetic configuration plan produced a Qman-specific workspace row with
read/write, execution, Git-read and writable-dispatch scopes. This does not
resolve the documented ACL traversal limits, protected-project requirements,
production gateway registration, relay configuration, or owner approval;
the draft discovery mechanism was not installed or applied.

## Relay / mapped-workspace mismatch — 2026-10-29

The current staging fixture enrollment registers the worker's mapped
publication path under `/var/lib/agentporter-bcc/publication-views`, while the
production-side natural registration is the canonical owner path. For the
existing disposable fixture, read-only `stat` confirms the two different
paths have identical device and inode. The relay client currently requires
the two registered path strings to be equal; therefore a canonical gateway
mapping paired with the existing mapped worker registration is rejected
before dispatch. The earlier in-process integration test used identical path
strings and did not cover this deployed BCC arrangement. A securely bound
cross-view identity protocol or another independently reviewed arrangement is
required; matching inode alone is not a completed authorization design. No
configuration or project content was changed.

Follow-up source inspection identifies a possible arrangement without changing
the relay protocol: register the same canonical path on both gateways and let
`WorkspaceTransaction` open the worker's separately provisioned mapped lower
and publication descriptors internally for a foreign-owned writable root.
The previously owner-run cross-owner transaction check used the canonical
fixture path and confirmed publication through those descriptors. That check
did not exercise relay dispatch or the worker's ordinary direct file tools,
and the current staging registration still uses the mapped path. Canonical-path
access, worker policy, real-project projections and a live end-to-end relay
must be verified before adopting this arrangement; it is not yet a fix.

Read-only host inspection rechecked the disposable fixture: canonical, lower
projection and publication view have the same device/inode; the canonical
owner is UID/GID 2056259175/2056259276, both views present UID/GID 997/997,
the lower mount is read-only, and the publication mount is writable. Projection
and publication parent directories were root-owned and not group/other
writable. This verifies the fixture prerequisites at inspection time only; it
does not register the canonical path, validate a live relay, or provision Qman.

Prepared a pure fixture-only configuration transformation in
`scripts/prepare-bcc-canonical-relay-fixture.py`. It proposes the same
canonical fixture registration for both sides, explicit worker relay read and
write scopes, and gateway public dispatch/write scopes while leaving the new
fixture absent from the worker's ordinary public-client policy. It refuses
existing relay policies/admissions rather than replacing them, and requires a
transactional provider-origin worker with bounded resource settings. Nine
synthetic planning tests passed. This function does not read or write live
configuration, install credentials, or apply the plan; actual policy
installation, cgroup supervision and end-to-end relay execution remain pending.

The generated synthetic worker and gateway documents were then loaded by the
actual workspace registry, public-client policy, relay scope and runtime-root
parsers. The worker's ordinary public principal was denied writable dispatch
to the fixture, while the gateway's explicit public grant and both private
relay scopes loaded successfully. The planning suite now has 10 passing tests.
This validates policy interoperability without installing credentials or
changing either live gateway; it is not an end-to-end service test.

A further synthetic integration test applied the generated documents to
disposable configurations and exercised the real public REST dispatch path,
production relay client, receiving ASGI relay, and a native Bubblewrap worker
with workspace transaction finalization. Unauthenticated dispatch and a push
request were denied, and an authorized fixture edit was published. Eleven
fixture-plan/integration tests passed. The transport is an in-process ASGI
bridge; provider admission is stubbed, credentials are synthetic, the resource
supervisor is a recording fixture, and both processes run under the test UID.
This is not evidence of live TCP, cross-owner relay execution, real cgroups,
provider execution, or production acceptance.

The same synthetic public-gateway integration now covers a worker that edits
its overlay and then exits 7: the canonical fixture remains unchanged, the
public job status reports `failed`, and the worker's marker remains available
through the public job-output endpoint. The success case reports `completed`
and publishes the fixture edit. Twelve fixture-plan/integration tests passed.
The same in-process, synthetic-credential, test-UID and recording-supervisor
limitations apply; this is not the live AP-06 acceptance test.

The integration was then strengthened to use a real loopback TCP listener on
an ephemeral port rather than an in-process ASGI transport. The relay client's
fixed staging destination was redirected only inside the test, and the
unauthenticated internal route was denied over TCP. Both successful and failed
native worker transactions and retained public output passed; the complete
fixture planning/integration module reports 12 passed. Provider admission,
credentials, service UIDs and resource supervisor remain synthetic, so this
does not establish live BCC service or cross-owner production behavior.

## Live staging resource observation — 2026-10-29

A bounded read-only staging fixture job `job_88386afa14d0494f92175311`
completed with exit 0 and the expected output marker. The worker had two tasks
before and after the probe. While it ran, one `apj_...` job cgroup was visible;
that cgroup was absent after completion. Its inner controller files were not
readable by the current user, so their CPU, memory and process values were not
verified. The cgroup-to-job association is inferred from the idle baseline and
timing, not independently identified by PID. The reproducible MCP probe is
`artifacts/bcc-acceptance-current/cgroup-live-probe.py`. This is staging-only
evidence, not a production gateway cgroup or AP-06 pass.

A second bounded fixture probe `job_528e774035284001b4e0777e` returned the
expected marker and exit 0. During the job, systemd showed the distinctive
probe command as host PID 849693 inside
`apj_e247862f90984e8c99710cad37ecdb4a`; `/proc/849693/cgroup` independently
reported that exact membership. The same cgroup was absent after completion.
This directly associates the observed process with the temporary worker
cgroup. The controller files and effective numeric limits remain unreadable
to the current user and therefore unverified; the template's values must not be
mistaken for live effective settings.

## Phil model provenance investigation — 2026-10-29

The installed Copilot CLI help offers `--model`, JSONL output and
`--usage-output-file`; its `--silent` mode suppresses statistics. GitHub's
[programmatic reference](https://docs.github.com/en/copilot/reference/copilot-cli-reference/cli-programmatic-reference)
also documents explicit model selection and JSONL output. These interfaces do
not by themselves establish a tamper-resistant actual-model receipt for a
confined AgentPorter job: model output and files writable inside the worker
cannot be treated as trusted provenance. The existing implementation correctly
reports `actual_model` as unknown rather than parsing worker-controlled text.
No new model was selected, no paid fallback was invoked, and no provider call
was made during this investigation. A separately protected provenance channel
or independently verified provider evidence is still needed to establish the
actual-model portion of seven-agent acceptance.

Provider-broker inspection shows the worker's network traffic passes through a
per-job broker that validates the upstream TLS origin, but it currently
forwards response bytes without parsing or retaining model metadata. Claude's
[streaming protocol](https://platform.claude.com/docs/en/build-with-claude/streaming)
documents a model field in `message_start` and also documents mid-stream
fallback, so a first-event model alone cannot prove the full job's actual
model. Any future broker-side provenance must account for response framing,
provider-specific schemas, all model calls and fallback, bounded parsing,
job association and cleanup; incomplete or ambiguous evidence must remain
`unknown`. No model-provenance implementation was enabled by this inspection.

## Liz pickup — atomic finalization and logging cleanup, 2026-10-29

Picked up Prof session `01a184b7-f168-76e0-a365-cbb6bde783d2` into Liz's
account. The historical `/tmp/agentporter-bcc-production-XCkSZH` source was no
longer present. All 98 preserved candidate-15 wheel package files matched the
current repository source before these changes. Candidate 15's focused packaged
suite passed 201 tests with one skip. Its baseline full run passed 2,600 tests
with 23 skips and 24 subtests, but two isolated-subprocess tests failed because
the disposable runner did not expose installed dependencies under `python -I`.
The runner was corrected without changing production dependencies or services.

Found and deterministically reproduced a capacity race: the async monitor
committed terminal job status before deleting its admission in a separate
transaction. A second manager could observe `completed` and immediately receive
`JobCapacityError`. The new regression failed before the fix. Terminal status
and successful admission deletion now commit atomically; failed cleanup still
retains capacity. Resource/cancellation/transaction checks passed 34 tests.

The full source run after this fix passed 2,603 tests but reproduced the logging
error. The error referenced a deleted REST integration fixture's temporary
`st/logs/agentporter.log`; the fixture retained process-wide logging handlers
after deleting the backing directory. The fixture now removes and closes only
handlers it created, before temporary-directory cleanup, and restores the logger
level. This is test-lifecycle cleanup, not suppression of broker diagnostics.

Final native source suite: **2,603 passed, 23 skipped, 24 subtests passed**, one
Starlette/AnyIO deprecation warning, in 116.14 seconds. No `Logging error`,
`FAILED`, or `ERROR` marker appears in the final log. The rebuilt installed
wheel passed 167 focused resource, cancellation, transaction, provider-broker
and isolated-launch tests. All 98 wheel package files match the final source.
This establishes the specific capacity fix and a clean full-suite run; the
historical resource failure's omitted traceback prevents conclusively proving
that it had exactly this cause.

Prepared candidate 16 at `artifacts/bcc-stage-20261029-16/`, pinned against
release 12. Wheel SHA256:
`ac21ba006d17747dbf8ecf8a335d60d5ebf10d92bd5da6f75054f9688acf7a3d`;
package fingerprint:
`a7b1962d76f4349f2c5fc4b680172c036b4f3a3de56f6fc420c82b647e673964`;
updater SHA256:
`b9f6bc05c9dca400fd54017ff8e1f9dfe3e8dea49f6b5f917970ceb19f397439`.
The updater's wheel-install function produced that fingerprint in a disposable
copy. Privileged updater execution and rollback were not performed. The wheel,
source/test archive, per-file manifest, packaged harness and logs are preserved
in `artifacts/liz-bcc-finalization-20261029/`.

Fresh read-only systemd inspection found staging release 12 active (PID 3393143),
production gateway active (PID 2686385), and `agentporter-openai-tunnel.service`
active. The legacy `bcc-tunnel.service` was inactive. The proposed system gateway
unit was not found; `user.slice/cgroup.subtree_control` still contained only
memory and pids. `sudo -n true` required a password. No live services or private
configuration were changed, and no commit or push was made. Source changes are
in the current worktree and are not deployed to the running processes.

Production remains **HOLD**: privileged staging activation/rollback, actual
gateway cgroup delegation and effective limits, independent owner signing,
trusted actual-model evidence, Qman provisioning/live relay, and final AP-01
through AP-06 acceptance remain unverified. Green source tests are not rollout
clearance.

## Production pursuit — release 16 live, 2026-10-29

Owner reported `STAGING_UPDATED`, `STAGING_ROLLED_BACK`, `STAGING_UPDATED`,
and `ROLLBACK_REHEARSAL_PASSED` for candidate 16's pinned installer. Independent
read-only service inspection found PID 937934 executing the immutable release
16 interpreter. Live authenticated deploy-info matched the exact expected
loaded/disk fingerprint `a7b1962d76f4349f2c5fc4b680172c036b4f3a3de56f6fc420c82b647e673964`,
with stale=false and the expected release package path. Unauthenticated access
returned 401. Through real MCP, fixture job `job_09e4cb1c94434af0990a8b43`
failed with exit 7 and retained its marker, then successor
`job_a2d6f8ac112c43a0bb835d81` completed with exit 0 and its expected marker.
Evidence: `artifacts/bcc-stage-20261029-16/live-verification.json`; reproducible
harness: `verify-live.py` in the same directory. This is live staging parity,
rollback/recovery evidence, not final production AP-06 certification.

A bounded Wei task `job_8b121766feb846c48cb3031b` launched under verified
confinement using its configured `opencode/glm-5.3-flash-free` model. It produced
no expected result within 40 seconds of dispatch returning and was cancelled
with status cancelled/exit 130. No substitution was made. Fixed-label diagnostics
found no authentication/quota/403/connection/server-error text. The cause is
not established; seven-agent success is not claimed. Sanitized evidence:
`artifacts/bcc-stage-20261029-16/wei-provider-smoke.json`.

Fresh private gateway inspection found no public-client policy, gateway budget
profile, or relay-upstream configuration. The legacy registry includes a broad
repos parent and writable AgentPorter/obsidian rows. Cutover must install reviewed
explicit scopes and transactional resource supervision with the immutable
package; it cannot be achieved by restarting the existing editable gateway.

Prepared an owner-run transient system-cgroup probe at
`artifacts/bcc-gateway-cutover-candidate-20261029/probe-system-gateway-cgroup.sh`.
It uses release 16 as yeli with Delegate=yes and CPU/memory/process service
bounds, refuses an existing system gateway unit, runs only supervisor --probe,
and checks transient-unit collection. It does not start a gateway/listener or
change production configuration. Bash syntax passed; actual host result is
pending the owner-run command.

Prepared a sealed independent approval-origin install at
`artifacts/bcc-owner-approval-candidate-20261029/install-independent-origin.sh`.
It pins all four assets, manifest, server script and DynamicUser unit; refuses
existing targets or any existing Tailscale Serve configuration; verifies copied
hashes and static health/security headers before tailnet-only HTTPS on port
8443. It does not enable boot startup or touch production AgentPorter/tunnel.
The existing host and signing protocol suites passed 59 tests. Installation,
actual HTTPS reachability and phone signing-key enrollment remain unverified.
The installed Tailscale CLI help and read-only status confirmed the flags,
empty Serve configuration, running backend, and BCC's matching certificate
hostname. No public Funnel was configured.

The rollout target remains the frozen six-criterion contract. Do not add a new
acceptance requirement merely to perfect model provenance: configured identity,
actual execution evidence, and no silent substitution must be honestly recorded;
unknown actual-model metadata remains unknown. Final independent certification
must follow `docs/bcc-production-acceptance.md` against the running deployment.

## Explicit provider fallback and real gateway unit validation

The owner explicitly authorized another reviewed free model for Wei, then Phil
if Wei rejected it. A request for `opencode/mimo-v2.6-flash-free` was rejected
by the installed dispatch policy before launching a job. This matches the
credential route's fail-closed model pin; no private profile or model was changed.
Phil fallback job `job_85294636bb48478db4b75c60` then completed under verified
confinement with exit 0 in about eight seconds and the expected result marker.
Actual model remains unknown. This is successful Phil staging evidence, not a
Wei PASS or seven-agent production acceptance. Sanitized receipts are in
`artifacts/bcc-stage-20261029-16/{wei-alternate,phil}-provider-smoke.json`.

OpenCode's public model-list endpoint still lists `glm-5.3-flash-free`, and its
current model documentation lists that model as free on OpenCode. Removal of
the model is therefore not established as the cause of Wei's stalls. Sources:
https://opencode.ai/inference/v1/models and
https://opencode.ai/v2/docs/console/models/ . No new inference request or paid
model was used for this availability check.

The production gateway unit draft now names the installed immutable release-16
interpreter directly, removing its nonexistent gateway-current path.
`systemd-analyze verify` returned zero against that real installed executable;
its emitted warnings concern unrelated netplan, snapd and page-inla host units.
No unit was installed or started. Actual system-cgroup probe output and protected
production scopes/resources/relay setup remain pending. The cutover checklist is
`artifacts/bcc-gateway-cutover-candidate-20261029/CUTOVER-GATES.md`.

## Gateway public-policy preparation — 2026-10-29

Added `scripts/prepare-bcc-gateway-policy.py`, a pure configuration planner with
no live reads, writes, credentials, service operations or deployment entry point.
It preserves existing registrations, ingress and API authentication settings;
turns on transactional/offline sandbox execution; emits explicit public-client
scopes and the separate bounded gateway resource profile. Public grants must
name individual registered BCC project paths, never the broad repos parent.
Registry read-only/exec/Git/dispatch denials cannot be overridden, writable
dispatch needs both explicit write and dispatch scopes, and existing hardened
or worker profiles require reconciliation rather than silent replacement.
No relay, signing authority or internal key is invented.

Native planning/parser/relay validation: **31 passed**, one existing
Starlette/AnyIO warning. Tests load generated documents through the actual
workspace registry, public policy and gateway budget parsers, confirm public
writes remain denied for unselected registrations and unsigned Git authority
is not granted, and retain the existing real loopback/native transaction relay
checks. Evidence: `artifacts/bcc-gateway-policy-plan-20261029/verification.log`.
This is configuration preparation, not a deployed policy or production PASS.
The source package remains byte-identical to the installed candidate-16 wheel;
only planning scripts/tests and review artifacts changed in this continuation.

Fresh host checks still showed the independent approval service absent,
Tailscale Serve empty, and sudo requiring a password. The transient system
probe result remains unverified without its actual console output. Existing
production gateway and OpenAI tunnel were not changed. Completion still needs
owner-run prerequisites, actual reviewed configurations and workspace/relay
provisioning, production migration/rollback, and frozen independent acceptance.

## System cgroup and independent HTTPS installed — owner result

Owner supplied a successful transient system-service probe: supervisor membership
verified at `/sys/fs/cgroup/system.slice/agentporter-bcc-gateway.service`, exit 0,
and `GATEWAY_CGROUP_PROBE_PASSED` after collection. This establishes the system
service's controller/bootstrap availability; it does not prove running gateway
job budgets or production acceptance.

Owner then installed the independent approval host. Read-only verification found
the DynamicUser service active (PID 1175696), Tailscale HTTPS port 8443 proxying
only to 127.0.0.1:18879, and all four HTTPS-served asset hashes matching the pinned
bundle. Security headers were checked. The transient gateway system unit was
not found after collection, as expected. Approval-host boot startup is not yet
enabled; no phone key was created or installed by this verification.

The owner reported a phone-browser timeout despite Tailscale being connected.
BCC's backend is running without health warnings; the iOS peer is online and
responded to both DERP and direct Tailscale ping. BCC resolves the approval
hostname to its correct tailnet IPv4 address and can retrieve the HTTPS assets.
These observations do not establish phone-to-BCC TCP/HTTPS reachability. Owner
was asked to try the exact /health URL in Safari and provide only packet-filter
fields from privileged Tailscale netmap output. Non-root debug access was denied;
no operator privileges, ACLs, firewall rules, public Funnel or alternate insecure
signing origin were enabled. Phone reachability and key enrollment remain open.

Prepared the bounded owner-run actual gateway preflight under
`artifacts/bcc-gateway-preflight-20261029/`. It uses a fresh private data root,
release 16, the real gateway service cgroup name and loopback port 18876; it does
not bind production port 8765 or retarget the tunnel. Its verifier checks real
PID/package parity, numeric CPU/memory/pids/swap controller values, worker PID
membership, cancellation/retained output/envelope removal and a clean successor.
The shell stops and collects the transient unit, retaining evidence and test
data. Shell syntax and Python compilation passed. The preflight has not been
executed; its proposed checks are not evidence of success.

## Phone HTTPS timeout diagnosed — tailnet policy

Owner-provided privileged output shows ShieldsUp=false and UFW inactive.
The effective BCC Tailscale filter admits the iPhone source addresses but only
TCP ports 22,139,445; it does not admit TCP8443. ICMP/ICMPv6 are allowed, which
explains why ping succeeded while the phone's HTTPS connection timed out.
The concrete missing permission is phone-to-BCC TCP8443, not a server-asset,
TLS-certificate, or local-listener failure.

Prepared an additive dual-stack grant in
`artifacts/bcc-owner-approval-candidate-20261029/phone-access-grant.json`.
It selects only the observed iPhone addresses and BCC addresses on tcp:8443.
It must be added to the existing tailnet policy's grants array through the
owner's Tailscale admin console, preserving existing rules. No tailnet policy
change has been made by this session. Phone HTTPS and key enrollment require
verification after the owner saves the grant.

## Phone grant applied via authorized Mac mini API key

Owner explicitly authorized use of Mac mini's `~/tail` API key to apply the
missing phone rule. Connected using the already-trusted 100.83.155.70 SSH host
record; the credential remained in remote process memory and was not printed
or copied to BCC. Read the current policy and appended exactly one grant:
source iphone171/iphone171-v6, destination bcc/bcc-v6, TCP8443 only. Existing
hosts, grants, SSH settings, node attributes and 23 tests were preserved.

The first write was rejected because the added test cases mixed source and
destination IP families; readback confirmed no policy change. Corrected the
new tests to use IPv4-to-IPv4 and IPv6-to-IPv6, then validated and saved with an
If-Match ETag to avoid overwriting concurrent edits. Final readback exactly
matched the proposal: six grants, 25 tests. Live API tests verify phone access
to8443 and denial of direct8765/18879 access for each address family.
Policy SHA256 (canonical sorted JSON):
`cd5af5de917da4131ddd9186fc31f8f7d9a134cd8fcd0693a60397e04d1d25db`.
Private pre-change backup on Mac mini:
`/Users/yeli/tail-policy-backups/20261029-112602-f3e555a9-before.json`.
Sanitized receipt: `artifacts/bcc-owner-approval-candidate-20261029/phone-access-api-receipt.json`.
Actual phone-browser success and public-key enrollment remain to be verified;
no signing key was created on BCC or Mac mini.

## Phone public key received — enrollment plan only

Owner reached the approval origin after the tailnet grant and supplied a phone
screenshot of public key
`dff57383a19abf8ea801de5365046d6dde10382cd69176026562c038e6518f73`.
Transcription is exactly 64 lowercase hex characters (32 bytes), accepted by the
Ed25519 public-key parser. No private signing key was received or generated.
Prepared `git-commit-policy.proposed.json` and `phone-key-enrollment-plan.json`
in the approval candidate directory, scoped only to the planned disposable
`bcc-git-acceptance` workspace, using the existing owner Git author identity.
No live Git policy or claim ledger was changed. Registration, private ledger
initialization, supervised gateway activation and an actual phone-signed receipt
still need execution; parsing the key is not proof of signing or enrollment.
The isolated system-gateway preflight had no result file and its transient unit
was not found at inspection time; actual kernel-limit tests remain unverified.

## First real gateway preflight — verifier startup race

Owner ran the isolated gateway preflight. Live process PID1362755 matched the
release-16 fingerprint and correct system-service cgroup. The verifier read and
passed the exact numeric budget assertions, then incorrectly required nonempty
cgroup.procs immediately upon envelope creation. It asserted before the Python
resource runner had joined the envelope and its finally block cancelled the job.
Retained job job_4af289dafc804dfab7186dcb is cancelled/130, duration0.0393s, with
empty stdout/stderr; there are zero retained admissions and the transient service
was collected. No launch-failure output exists; this test did not wait long
enough to establish worker startup or its failure.

Corrected the verifier to wait for the workload output marker before reading
cgroup membership, independently associate surviving PIDs, and tolerate only
launch wrappers that have exited during inspection. All budget, membership,
cleanup and successor assertions remain required. Added --resume mode that
checks private directory ownership and refuses active/unresolved jobs or
admissions before reusing the disposable configuration. Executed those read-only
resume checks successfully. Shell syntax and Python compilation passed.
First-attempt evidence was preserved in the preflight artifact directory.
Actual corrected preflight is pending owner sudo authentication; no full
kernel-limit/cancellation/recovery PASS is claimed yet.

## Gateway kernel-budget preflight passed; disposable phone enrollment

Owner reran the corrected preflight with --resume. Read-only evidence copied to
`artifacts/bcc-gateway-preflight-20261029/verified-result.json` confirms PID1364474
matched immutable release16; actual cpu.max200000/100000, memory.max2147483648,
pids.max128 and memory.swap.max0 were read, with three process memberships
independently associated to the job cgroup. Job job_fa32e88c205b4c8cb38eaf18
cancelled/130, retained its marker, and its envelope disappeared. A clean
synchronous successor exited0. Independent post-run inspection confirms zero
admissions and the transient service not-found/inactive. This is a real gateway
system-service test on18876, not a production cutover or final AP certification.

Enrolled the supplied phone public key only into that stopped disposable gateway.
Created a separate synthetic bcc-git-acceptance repository, an operator-created
baseline commit9a5ab4fad33e521a9cb0968545b71062a3a5e4bf, private owner-Git claim
ledger and exact commit policy scoped only to that repository. Enabled explicit
read/write/exec/Git-read/Git-write/commit client scopes there; no fetch/push or
worker dispatch was granted. Production policy/configuration was not changed.
The key has not yet been verified by an actual phone signature.

Added --signing-session to the owner preflight launcher: it resumes the isolated
configuration, reruns the gateway checks and leaves only port18876 active for
phone signing verification, with RuntimeMaxSec1800 and the explicit owner stop
command. Bash syntax passed. This session mode has not yet been started; no
phone-signed commit has been made.

## Phone proposal transfer repair — linked proposals prepared

Repeated phone copy/paste produced Invalid JSON value and Unterminated string,
while the exact generated proposal passed the protocol parser/digest check
locally. Review correctly kept acknowledgment/signing disabled; no receipt or
commit was produced. The manual JSON transfer is a demonstrated workflow blocker.

Added bounded base64url proposal loading from the approval URL fragment. The
payload is decoded locally with strict UTF-8/JSON parsing, prior review is
invalidated, the fragment is removed from the address bar, and explicit Review,
acknowledgment and trusted signing click remain required. No network fetch,
message signing interface, key replacement or automatic signature was added.
Malformed links fail closed. Existing manual paste remains supported.

Browser/protocol gate:45 passed, including real synthetic browser signing/key
persistence, malformed-link rejection, no automatic approval, trusted-click
requirement, stale-input invalidation and no external requests. Prepared pinned
root-asset update at `artifacts/bcc-owner-approval-link-update-20261029/` with
backup of the installed original app/manifest before copying and HTTPS hash
verification after the independent host restart. New app SHA256:
`c107b244b02ce1fe2d60d8b09e585e760786fb960af186c0402e6499286bb14d`.
Installation has not yet occurred. Source app.mjs now differs from candidate16's
packaged static asset; the running gateway's package was not changed. The
independent approval origin's asset release is tracked separately.

## Actual phone signature executed — isolated immutable gateway

Owner installed the pinned linked-proposal page update; HTTPS app hash was
independently matched. A fresh exact proposal was delivered through the URL
fragment rather than damaged clipboard JSON. Owner returned a real device
signature for request digest8dee35bb934b39bb943360d8c8ea560a9cb06bc98c3be9f7844973d06f5e8e55.
The isolated gateway's authenticated REST commit endpoint accepted that receipt
and produced commitda6097ca10e55ea95c9be65ead25195b3bcb950a. Native Git inspection
verified exact parent9a5ab4fad33e521a9cb0968545b71062a3a5e4bf,
staged treee047f88dbcc745ebf887de3735cff76530bf4857, commit message, approved
file content and clean worktree. Reusing the same receipt returned403. The
private claim ledger independently contains the exact nonce/digest, with zero
remaining job admissions. No private key left the phone.

Evidence under `artifacts/bcc-gateway-preflight-20261029/` includes the linked
proposal, consumed signed receipt, staged diff, preparation checks and
phone-signed-commit-result.json. This verifies actual device approval and a
supervised immutable-gateway commit in a disposable repository, not final
production AP-03 or certification by an independent auditor. The temporary
signing service remains bounded by its original30-minute runtime; production
port8765, gateway config and OpenAI tunnel remain unchanged. Remote Git
fetch/push, actual production relay/project provisioning, immutable cutover and
frozen AP-01 through AP-06 acceptance remain unfinished. Owner was asked to
select an existing disposable HTTPS repository for remote acceptance rather
than inventing publication authority.

## careDX selected for protected remote acceptance

Owner selected https://github.com/lennon-li/careDX for the remaining signed
fetch/push test. Read-only GitHub inspection confirms private, not archived,
read/write account access, default branch main at
87b253af83fd9e36718271576e183152c6cf1b63, and no existing branch named
agentporter-acceptance-20261029-phone. No remote ref was changed.

Prepared a protected remote policy only in the isolated gateway: careDX remote
identity, exact HTTPS .git URL, fetch permission solely for refs/heads/main and
push permission solely for refs/heads/agentporter-acceptance-20261029-phone.
The existing phone public key and private claim ledger bind both operations.
A GitHub credential was obtained through gh's standard authentication interface
and stored0600 in the private owner-Git directory outside every exposed root;
it was not printed or put in command arguments. Explicit public fetch/push
scopes were added only to bcc-git-acceptance, with a pre-change scope backup.
The actual immutable package's remote policy parser accepted the result and
confirmed push to main denied. Running gateway activation requires a restart;
no signed fetch/push request has yet been prepared or executed. Production
configuration remains unchanged.


### Owner revision: autonomous local commits, no agent pushes (2026-10-29)

The owner rejected phone approval for local Git commits and requires every agent,
including ChatGPT, to commit in writable workspace repositories while agents may
not push. AP-03 and AP-05 now reflect this explicit revision.

Implemented in the working tree: `WorkspaceGitCommits` reuses the bounded,
resource-supervised, network-isolated commit backend, workspace mutation lease,
sealed Git configuration, compare-and-swap refs and durable recovery guard without
an external signature. The server selects this backend only for supervised
transaction-enabled runtimes. Public commit permission follows workspace write
scope; the registry still requires writable Git access. Both the Git tool and
operator action boundary deny push, including legacy backend enablement and old
receipts. Production has not been restarted or changed.

Validation: 47 focused native tests passed, covering receipt-free commits,
parent/tree preservation, read-only denial, legacy push backend denial, existing
commit safety tests, operator modes and public-client boundaries. One existing
Starlette/AnyIO deprecation warning remains.

BLOCKER: delegated worker shell commits still encounter the existing read-only
Git metadata/transaction publication boundary. Two proposed changes to permit
restricted Git history metadata publication were rejected by automatic approval
review, including after explicit owner approval; neither proposed sandbox change
was applied. Review cited an insufficiently narrow/validated persistent security
boundary across writable workspaces. No replacement release or production
acceptance is claimed. A safer delegated commit bridge or separately validated
transaction publication change is required before cutover.


### Receipt-free local commits: release 17 candidate (2026-10-29)

The previous sandbox-publication proposal was replaced with a narrower private
Git design. A writable transaction snapshots conventional repository metadata,
including nested repositories, into private job storage. After complete job
quiescence, fixed supervised offline Git code validates fast-forward ancestry,
exports a bounded object pack, imports verified objects and the exact staged
tree, and compare-and-swaps a local branch. Canonical hooks, configuration,
remote credentials, alternates and arbitrary Git control files never cross back.
The ordinary workspace delta validator still rejects every .git path. Failed or
cancelled jobs discard private commits. Interrupted publication retains guards;
the generic file recovery tool refuses to clear private Git import guards without
operator reconciliation.

All seven named worker launch paths passed real native confinement/commit tests
using synthetic offline worker code. This is not a claim of seven provider quota
passes. The runtime now scans and inherits the exact pinned owner-mapped lower
for foreign-owned workspaces and closes setup descriptors before worker code.
Direct REST/MCP commits require writable workspace membership, with no external
signature. A protected local claim ledger preserves the existing API commit
recovery checks; an interrupted-result regression passes without phone approval.
Agent pushes are denied at both the operator policy and direct tool boundary,
even with old push scopes, backends or receipts.

Final native gate: 2,645 passed, 23 skipped, 24 subtests passed. Installed-wheel
focused gate: 209 passed. One existing Starlette/AnyIO deprecation warning.
The candidate and exact hashes are in artifacts/bcc-stage-20261029-17/PINS.json;
source/wheel byte parity covers 99 package files. The pinned installed worker
unit and release-16 manifest match the update baseline. Shell syntax, Python
syntax, artifact hashes and git diff whitespace checks passed.

`install-and-verify.sh` installs candidate 17 in the isolated worker, then runs
a disposable gateway under actual system cgroups. Its new live canary requires
native-shell and REST commits without phone receipts, denies push with and without
legacy receipts, and checks canonical Git configuration preservation. No extra
rollback rehearsal or phone signing session is requested. Sudo still requires the
owner's terminal authentication, so this live gate and production cutover are
NOT VERIFIED. The current production gateway/tunnel have not been changed.
The pure production project/relay policy transform has six passing tests; actual
project projection/relay provisioning, cutover, and final acceptance remain pending.


### Release 17 live gate passed; production boot/cutover operator prepared

The owner reported complete success from the corrected release-17 installer:
worker PID 1519429 and disposable gateway PID 1519487 matched immutable package
fingerprint 7e6b67494ddb1748e9b91fffe7af6efab5b15be3498f3ace41c7e27072bbadb2.
Real kernel limits, cancellation, envelope cleanup and clean successor passed.
Native shell commits and receipt-free REST commit e3e33bd1bcc39d989950b893ea1fdc2b3243f82a
passed. Push with/without legacy receipt returned 403; canonical config hash was
preserved. The transient gateway was stopped and the tunnel/production remained
unchanged. Subsequent read-only inspection verified the active release-17 worker
and the absent transient system gateway.

The owner clarified: retire the old gateway process, retain MCP and Actions/REST,
and ensure AgentPorter starts with the system. The production operator bundle is
artifacts/bcc-production-cutover-20261029. It creates private backups and explicit
project/relay scopes, provisions boot-persistent owner-mapped views, and tests real
worker project execution plus a native canary commit before stopping the old
service. It then disables the legacy user gateway, starts the immutable system
gateway with unchanged public URL/API key, preserves the active tunnel PID,
verifies canary commits/push denial and seven-worker scope, and enables multi-user
boot. The tunnel dependency on the retired user gateway is reset in a drop-in.

A regression demonstrated that the initial maintenance trigger did not cover
synchronous admissions. A small validated change adds a second rejecting trigger;
exact nonce ownership, active-work checks and refusal to overwrite owner edits
remain enforced. No recovery CLI or workspace sandbox boundary was weakened.
Cutover/relay/policy tests: 41 passed, one existing dependency warning. All three
unit definitions validated against the installed release (exit 0); unrelated
host netplan/snapd/page-inla warnings persist. Launcher component pins, privileged
hash checks, Python/shell syntax and whitespace checks passed. Thirteen actual
Git layouts passed read-only metadata checks. No production cutover has run yet:
noninteractive sudo still requires the owner's terminal password. Final phone,
provider quota, genuine scientific workflow and independent acceptance remain
unverified; the operator does not claim their completion.
