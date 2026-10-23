# Project access acceptance correction and guarded reactivation

**Live closeout verified, 2026-10-22 UTC / October 21 Toronto:** The owner completed the recovery without errors. A7Dev now runs release `20261021T232414.837654Z`, PID **886920**, zero restarts. Independent public/local MCP checks match loaded/disk fingerprint **`099b88c95f0fb23e33554e85a426e1b25b9fbba9ca3fe4fffd1ab4869b5da315`**, stale false, same PID. All **41 ordinary projects** are admitted for public read-only delegation; the owner's corrected live acceptance completed all read/write/offline-execution and denial checks. Production A7 remains active at original PID **664960**, zero restarts, unchanged by this work. **Do not rerun the recovery command below after this successful activation.**

Jax public jobs `job_2dbdd2acf75f44ea9c1d5421` (Qman) and `job_2a4b547ecaa04191aebcbda3` (m3-poc) are independently confirmed **completed, exit 0**. The owner-run hash-pinned validator checked the unpredictable file checksum challenges; raw native trace events were not separately available in persisted job results, so an independent replay of that trace is not claimed. Wei's configured free route is live verified. Public `tools/list` includes `https_download` with 16 MiB/60-second defaults; the saved requested 2022 snapshot was rehashed and gzip-verified through public offline execution. [Sanitized live evidence](evidence/a7dev-project-access-retry-20261021/live-closeout.json).

Historical cause: the owner first installed the reviewed release, applied the exact approved 41-project scope, and ran public acceptance. All 41 ordinary projects passed directory listing, offline Python and temporary create/read/delete probes. Acceptance incorrectly required root directory listing for `agentporter`, `AgentPorter` and umbrella `repos`, triggering a successful rollback. The correction and reviewed reactivation below subsequently resolved that acceptance failure.

## Cause

Actual host `getfacl` shows `user:agentporter-dev:--x` on `/home/yeli/repos` and `/home/yeli/repos/AgentPorter`. The three workspace IDs refer to these two traverse-only roots. Their listing denials are intentional existing ACL boundaries. The validator incorrectly treated those denials as project-access failures. No ACL grant or sandbox relaxation is needed.

The corrected external validator records `read:false` and `listing_denied_expected:true` for those three roots. It rejects unexpected listing success there. The other two protected scopes must still pass listing; all protected execution/delegation remains denied. All 41 ordinary roots must still pass the complete read/write/offline-execution checks, effective runtime delegation admission, Git checks and network/host/method/redirect/protected-path denials.

## Completed recovery command — historical reproduction only

```bash
cd /home/yeli/agent-work/agentporter-dev
bash scripts/resume-a7dev-project-access.sh
```

The owner already executed this approved command successfully. **Do not rerun it or `install-a7dev-project-access.sh`**: the intended release is active and all backup paths exist. Further recovery would require reviewing the actual current state rather than repeating these completed mutations.

The recovery runner reuses the already installed, independently reviewed package; no new archive or release is built. It:

1. Verifies all 26,359 installed entries against the pinned manifest, immutable root ownership/modes and symlink containment.
2. Authenticates the exact original rollback receipt `.candidate-482d30fb1a69a9aa75dc7f5ff88250fe`, compares its previous runtime and all four original configuration backups with the recovered current state, and checks for zero active jobs/admissions.
3. Stops only A7Dev and preserves the exact rolled-back policy recovery under a new private archive using atomic no-overwrite rename. Existing receipts are retained.
4. Freezes hash-verified inert runtime bytes into the new root-private backup, restores the reviewed runtime and atomically selects the existing release. Python helper/validator code executes only as the service UID; only standard installed system programs perform privileged operations. The existing immutable installer is used solely for guarded rollback if needed.
5. Reapplies the same exact approved plan SHA256 `2c4b78429001d4a3f3e5acdfa074d2a0ea5987a3980b04e6d378177d5f9c196c`, starts A7Dev, and runs the corrected external public acceptance.
6. Confirms production PID/release are unchanged. After access/scope/security checks pass, performs real read-only Jax checksum challenges in Qman and m3-poc. A provider quota failure does not undo validated access.

The original immutable bundled validator is preserved and is deliberately **not** used for this corrected check. Corrected external validator SHA256: `0c85c0548797076ef71faba9a8c276abefcb6c659c9d1d693be69fa79c49c39b`. No claim that it matches the original bundled script is made.

If pre-provider acceptance fails, rollback restores the exact previous policy/registry/runtime/release pair and verifies all four configuration bytes before restarting v19. Unknown drift, inability to establish stopped/quiet state or a rollback failure keeps A7Dev stopped for inspection. No SQLite backup is restored and no research data or production state is modified.

## Verification

- Corrected classifier regressions: **19 passed**. Retry evidence-preservation preflight: **17 passed**. Combined focused policy/classifier/preflight suite: **65 passed**.
- Parent and independent reviewer each rehashed every actual installed payload entry: **26,359 matched**, no mutation. Readonly mode checks passed.
- Independent reviewer reran the classifier/preflight regressions (**36 passed**), all **17** simulated recovery scenarios and **six** runtime-template safety cases. [Final independent review](evidence/a7dev-project-access-retry-20261021/independent-recovery-review.json) passed. Reviewed runner SHA256: `0bc6336986aac04ab5a745395f166f1da8df03daf899a6458050d7524ba8d2dd`.
- The original immutable release previously passed **1,568 tests + 24 subtests** in both source and exact-artifact gates. No installed application code has changed since that review.
- Owner-reported successful project probes and rollback were reconciled with the corrected classifier. The subsequent successful owner reactivation and fresh parent public/local scope, job and saved-binary checks are recorded in `live-closeout.json`; no new provider jobs were dispatched by the parent.

Evidence: [corrected classification of owner-reported acceptance](evidence/a7dev-project-access-retry-20261021/owner-reported-acceptance-classification.json), [installed payload verification](evidence/a7dev-project-access-retry-20261021/installed-payload-verification.json), [evidence index](evidence/a7dev-project-access-retry-20261021/sha256.json).

Preserved original owner backup: `/var/backups/agentporter-dev-project-access-20261021T232414.837654Z`. Successful reactivation evidence: `/var/backups/agentporter-dev-project-access-reactivation-20261021T232414.837654Z`. Service-private acceptance directories: `/tmp/a7dev-project-access-verification-0hyk9xi2` and `/tmp/a7dev-project-access-verification-f2jy3sbx`. Their private permissions were preserved; independently queried public evidence is exported instead.

Wei's free model, credentials/accounts, strict egress, Cranary-only HTTPS, binary limits and production protections are unchanged. Phil remains deferred and Argie's unexplained ACL request stays blocked. No ACL changes, model training, commits or pushes occurred.

ChatGPT's account-side tool refresh remains outside this session's control. If the imported `https_download` tool is still missing, refresh the existing a7dev connection and start a new conversation. Server discovery and invocation are verified; the account-side cache state is not claimed. This access repair does not declare the wider production rollout complete.
