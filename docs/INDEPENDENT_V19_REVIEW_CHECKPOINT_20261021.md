# Independent v19 review checkpoint — 2026-10-21

**Review target**: `review-artifacts/agentporter-cranary-hardened-v19.tgz`, SHA256 `701b295e396118b75d09a6ee6c72bd251bbfc05c7a22cf4eb21f061f0136ce80`. No installation authorized or performed by this review.

## Independently checked through live A7Dev

- Recomputed the archive SHA256: exact match.
- Reviewed the local agent's pinned full-streaming archive audit and 12-file delta from v17-install-r3; the report passed for 26,357 payload entries, 74 package files, package fingerprint `2a41380b67529e5bb27fa3e00d7a84ced0946989879b3948a97c25f5eeee6ac7`. This audit was authored/run by the implementing agent, so its pass is evidence rather than wholly independent artifact-signoff.
- Read the packaged acquisition acceptance verifier, which verifies matching public/local PID and fingerprint, public generic-shell denial, strict host/path/byte/time denial, and separate direct-loopback internal credential for offline consumer checks.
- Reviewed the source delta: explicit public `https_download` authorization mapping; new dedicated bounded GET worker; dated-Posit/CRAN path restrictions; fixed research receipt-directory publication; and metadata/REST/MCP registration.
- Implementer regression evidence reports full source and exact extracted artifact suites of **1,516 tests + 24 subtests each**, no skips or deselections.
- Verified current A7Dev is **still v12** PID 4102155, loaded/disk fingerprint `04a978d2746a88afe79c56af673e6d19850ef24aca9b382becc14426fa8a4fcd`. A7 production is still PID 664960, fingerprint `8de423283d3db8938a226719650a6c3b8fb325c534154992636bb6c51bf490a8`.

## Not cleared by these checks

1. Running native service does **not** yet include scoped Posit, binary download, delegated CPU/memory/pids cgroups, or new public-client policy. These are installation acceptance gates.
2. The protected immutable root installer and systemd drop-in were not accessible for independent host-owner inspection here; obtain trusted owner-side SHA/ownership/ancestor verification before running anything privileged.
3. Actual live systemd delegation and resource isolation, per-job subtree cancellation, public/internal ingress isolation, live download, and live rollback remain untested.
4. Enabling strict provider-origin broker imposes **known Argie loss of availability** at the blocked `writeTrajectoryAcls` endpoint; accepting that change is an explicit owner decision. Phil remains deferred.
5. Installation/rollback procedures use multiple privileged commands and are **not atomic in the database/OS transactional sense**. Treat the stopped-service preflight, exact backup, receipts, interrupted-install recovery and validation as mandatory. The owner must supervise rollback on any failure, not rely on shell `set -e` alone.
6. Existing Cranary historical population, reuse rights, training eligibility and independent scientific review remain unresolved even after network acquisition.

**Decision:** combined artifact is a credible installation candidate; source and offline artifact testing are complete. It is **not independently certified for live deployment**. Stop before protected writes or restarting either service until the owner explicitly accepts the Argie restriction and the exact upgrade policy, then have the trusted local operator verify protected preflight and perform a controlled A7Dev-only installation with all documented post-install checks. Never touch production A7.
