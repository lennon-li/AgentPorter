# Production delegation readiness (2026-10-20)

Decision: NOT SAFE to enable delegation in the current production service. This document is evidence, not deployment approval.

## Gateway status
- Production A7: all seven agents blocked_pending_os_confinement.
- Development A7Dev: all seven identities pass OS-confinement checks; only some complete real provider-backed calls.
- Development service runs under separate agentporter-dev UID on 8876. Production's existing owner-managed release still lacks that external worker boundary. Copying its development configuration into production UID is not an acceptable substitute.

## Real agent task results
- Prof: independent read-only security audit successful; initial wrong absolute project root was corrected by using /workspace.
- Liz: task successful on disposable workspace; writable task dispatch against agentporter-dev failed once and needs diagnosis.
- Ming: real provider task successful.
- Argie: real provider task successful.
- Jax: model-provider refresh / connectivity failure; job cancelled.
- Wei: API key expired (provider error).
- Phil: Copilot monthly quota exceeded (provider error).
- Readiness UI must distinguish OS-confinement-ready from provider-task-ready.

## HTTPS audit findings and development fixes
Prof identified HEAD header injection, config policy ancestor/path swap, and percent-encoded credential query names. Fixed in src/agentporter/scoped_https.py:
- HEAD output uses only numeric status, rejects control bytes in permitted headers, bounds total generated header bytes.
- Operator policy uses fd-pinned no-symlink directory traversal with trusted-ancestor checks; opens policy relative to pinned directory handle.
- Query parameter keys are percent-decoded before denylist inspection.
- Confined task packet in src/agentporter/agents/broker.py now says Project Root: /workspace, matching the worker mount.
- Tests expanded: tests/unit/test_scoped_https.py and tests/verify_https_audit_regressions.py.

## Verified test evidence
- 65 original offline HTTPS security cases PASS.
- exec_run/exec_start HTTPS integration verifier PASS.
- Standalone offline regression verifier PASS including real directory rename-and-replace attack simulation.
- Python compile/AST and git diff --check PASS.
- Prof independent second audit found all three fixes effective and caught test literal escape errors; those test errors were corrected.
- Full post-change pytest suite NOT run: this gateway's exec sandbox exposes Python 3.12, but the project environment has Python 3.13 extension wheels. The older 1,003 test result predates these edits, and must not be misrepresented as a post-change pass.

## Remaining gates before production
1. Run post-change full Python 3.13 tests on a trusted, isolated host build.
2. Repair Wei API key and investigate Jax provider route; Phil provider quota requires reset or alternate authorized provider.
3. Review a production broker that forwards explicitly authorized tasks to separately isolated worker identity with protected credential / workspace mappings. Do not enable unconfined workers under production UID and do not retarget production tunnel silently.
4. Verify independent live dispatch, negative cross-workspace and credential tests, deployment rollback, and actual provider success per identity.
5. Use the owner-controlled immutable release process only after review and validation.

Production gateway, secrets, tunnel, service processes, Git commits, and remote repositories were not changed by this work.
