# AgentPorter v19 closeout — access restored

**Latest live checkpoint:** Approved project-access repair release `20261021T232414.837654Z` is now running, PID 886920, public/local loaded=disk fingerprint `099b88c95f0fb23e33554e85a426e1b25b9fbba9ca3fe4fffd1ab4869b5da315`, stale false. All 41 ordinary registered projects are admitted for public read-only delegation; corrected owner acceptance passed project access and security denials. Jax completed real jobs in Qman and m3-poc (exit 0), Wei's free configuration is verified, and the requested 2022 snapshot remains intact. Production A7 is active on unchanged PID 664960. See [final reactivation closeout and evidence](A7DEV_PROJECT_ACCESS_RETRY_20261021.md). The earlier v19 checkpoint below is historical; its two-workspace delegation limit and fingerprint have been superseded.

2026-10-21, Asgard. **A7Dev workspace access and Cranary acquisition are live verified.** All 46 registered workspaces are visible. Qman, IRVRI and Cranary passed public workspace-info, pwd, Python and Git checks. No additional owner action is required for these workflows. This is not production security clearance or a claim that every earlier rollout gate passed.

## Installed state

- Release: `20261021T212000.000019Z`, immutable v19 archive SHA256 `701b295e396118b75d09a6ee6c72bd251bbfc05c7a22cf4eb21f061f0136ce80`.
- Public/local loaded and disk fingerprint: `2a41380b67529e5bb27fa3e00d7a84ced0946989879b3948a97c25f5eeee6ac7`, stale false, same process PID 530299.
- All 26,357 actual installed payload entries matched the audited manifest; root-owned immutable files/directories verified. Evidence: `installed-manifest-verification.json`.
- Production A7 user service remains active, PID 664960, zero restarts. No production service/configuration changes occurred. Its loaded fingerprint was not freshly queried.

## Root causes and repairs

1. The installed two-workspace public-client policy denied ordinary offline execution and excluded IRVRI/Qman. Following explicit owner direction, the owner applied `scripts/restore-a7dev-workspace-access.py` (SHA256 `59afe7cf5c925f016fdd3694aa353cee93ae1a361f9dda795d286924d9ac1703`) and restarted only A7Dev. Active policy SHA256: `97fbbeb9abfb896f4022647218dbc77f80fbfa2bbb3bfea25101756dd4b92043`. Ordinary projects have scoped read/write/offline exec/Git-read. Obsidian, production-source aliases/exposure root and their umbrella `repos` stay read-only. HTTPS remains Cranary-only; no new publishing or delegation scope.
2. GitHub host/GET/HEAD authorization already works. Legacy rrlite URLs reproduce exit 77; direct canonical `ropensci-archive/rrlite` commit/source calls succeed. Redirects remain forbidden; the redacted legacy error does not establish its exact HTTP status. No GitHub grant expansion was required.
3. Saving binary HTTPS uses dedicated `https_download`, not `curl -o`. Owner policy fixes destination, HTTPS/443, dated paths, 16 MiB, 60 seconds, public-IP/TLS checks, no redirects, checksum receipts and no-overwrite publication. `curl -fsS URL` and `curl -sSI URL` remain bounded metadata-only commands.
4. The first post-install attempt preceded HTTP readiness; waiting for `/health` corrected the procedure. Three hash-verified source-evidence directories also needed service read/traverse ACL restoration. No package code or sandbox rules were changed. An orphan Prof job was independently verified dead, privately backed up and marked interrupted; no PID was signalled and no admission deleted.

Exact working payloads and bounds: [Cranary guide](CRANARY_A7DEV_WORKING_PAYLOADS_20261021.md). Workspace IDs are case-sensitive: `Qman`, `IRVRI`, `cranary`.

## Live acceptance — executed through public A7Dev

All six latest Cranary acceptance requirements passed in `restored-workspace-acceptance.json`: Python, Git, frozen GitHub commit/source retrieval, bounded Posit download, offline decompression/SHA256 and network denials. Public and literal local endpoints matched the installed fingerprint/PID. Additional Qman and IRVRI offline commands passed. Direct Python socket access to public IP 1.1.1.1:443 failed with ENETUNREACH (101); generic networking was not enabled.

- Posit snapshot: HTTP 200, 710,490 compressed bytes; SHA256 `a069c3138f2b49c339d5f500f8beff8872d95a125e61a01b8307a7a6eba214fd`; prior-receipt checksum enforced. Saved `data-raw/cran-history/reports/2026-10-21-authorized-acquisition/downloads/PACKAGES-v19-acceptance-a167ea485e86b228.gz`.
- Offline expansion: 3,255,263 bytes; SHA256 `2b70321658ff7c6bd3159b62ed8f28708d3544d1b6dce8aa7ce443dc17296280`.
- Frozen rrlite commit `b390ba0afb5f1613572ba4ce3d5d733987edd0bd`; decoded source 4,271 bytes, SHA256 `015761af6d0374967c6eb563b211eab208b3b9572673176e659c74fb1d107007`, Git blob `bba6bf7f836a0ebdc52f2554ab32b8bd7410ed1d`. API JSON and `.c` saved with fresh exclusive filenames `rrlite-a167ea485e86b228-source-api.json` / `rrlite-a167ea485e86b228.c` in the same directory. API-byte checksum recorded separately.
- Earlier CRAN TCIU test: HTTP 200, 4,257,339 bytes; expected SHA256 `f9859ceb56997d30041c90f45073e59afd32f8ba985e0c6d500a6f49a2d98a42` verified and saved bytes independently rehashed.
- Seven final denial cases passed, including unauthorized host, POST, redirects, IRVRI network access, protected-root execution and protected absolute file access. Earlier 15 acquisition denials also passed. The earlier test expecting Cranary offline exec denial was intentionally superseded by the owner's restored scope.

Provider-backed native challenge checks passed for Jax (Headroom route preserved), Liz, Prof and free Wei. Each matched an unpredictable challenge hash, saw shared skills/toolkit and could not see gateway/production paths. Exact actual-model metadata for Codex identities remains unknown. Ming's tested attempt was externally quota-blocked; no later retry/account substitution. Phil remains deferred; Argie's unexplained ACL request remains blocked. Details: `native-workers-live.json`.

## Remaining limitations and rollback

The raw Posit index contains 17,802 records / 17,785 normalized families, with 17 repeated families and conflicting RODBC/XML versions. The existing research population preview correctly refused ambiguity. Source bytes and integrity checks were preserved; no row filtering, version selection, frozen-dataset modification or training occurred. Acquisition is usable independently of population-selection review. The original combined verifier therefore failed at the research consumer; its full pass is not claimed.

Aggregate kernel cgroup controls match: 16 GiB/no swap, six CPU equivalents, 512 tasks. Native job cgroups appeared and were removed. Yeli could not read their private control files; actual per-job budget readback, live detached-descendant cancellation and live rollback are **NOT verified**. Earlier exact-source/artifact gates passed 1,516 tests + 24 subtests each; these do not replace unperformed live checks. No broad test/development cycle was restarted.

- Exact immutable install/runtime rollback pair: `/opt/agentporter-development/.candidate-4938f071c6098efd8e4ded18ce4b6df3`.
- Original owner backup: `/var/backups/agentporter-dev-cranary-v19-20261021T212000.000019Z`; stopped DB snapshot `jobs-before-v19.INk7jhDw`; orphan-recovery receipt `prof-orphan-recovery.FCOEik5y.json`.
- Policy-only rollback backup: `/var/lib/agentporter-dev/config/public-client-policy.before-workspace-restore.yaml`. Hash-pinned helper `--rollback` restores the original two-workspace policy and requires an A7Dev restart; it would intentionally remove restored project access. Do not invoke for ordinary research-data ambiguity.
- Full release rollback follows the original handoff with this new install receipt and exact old runtime/HTTPS bytes. Its public-policy guard must now expect active hash `97fbbeb9abfb896f4022647218dbc77f80fbfa2bbb3bfea25101756dd4b92043`, rather than the superseded two-workspace hash. Preserve all backups and acquired bytes; do not blindly restore SQLite over newer jobs.

## Evidence and changes

Evidence: [index](evidence/v19-final-closeout-20261021/sha256.json), [latest public acceptance](evidence/v19-final-closeout-20261021/restored-workspace-acceptance.json), [acquisition receipts](evidence/v19-final-closeout-20261021/acquisition-receipts-final.json). Reproduction script for this exact run: `restored-workspace-verifier.py` in the evidence directory. Earlier checkpoint narrative is preserved as `closeout-checkpoint-history.md`.

Session changes include the owner policy helper/example, exact payload guide, closeout/evidence, one-off orphan/consumer diagnostics, read-only challenge and the local Wei verifier's 40→90 second client deadline (cold inventory took 48.8 seconds). Installed v19 package code remains unchanged. Inherited dirty detached worktree and unrelated changes were preserved. No commits, pushes, new release deployment or model training followed the owner's final acquisition handoff.
