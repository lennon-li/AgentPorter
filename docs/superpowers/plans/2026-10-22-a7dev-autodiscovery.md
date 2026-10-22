# A7Dev Automatic Discovery Implementation Plan

> **For agentic workers:** Use subagent-driven-development for the bounded implementation and an independent final security review. No commits or pushes.

**Goal:** Automatically expose eligible new `~/repos` projects with current ordinary-project permissions.

**Architecture:** A root-owned isolated Python reconciliation helper updates the existing registry, public policy and worker allowlist together. A 30-second systemd timer invokes it; transactional admission guards prevent interrupting jobs while allowing gateway startup writes during reload.

**Tech Stack:** Python 3, PyYAML, POSIX descriptors/ACLs, SQLite, systemd, pytest.

**Spec:** `docs/superpowers/specs/2026-10-22-a7dev-autodiscovery.md`

## Global Constraints

- Only direct real yeli-owned directories under `/home/yeli/repos`; no protected, hidden or symlink roots.
- Offline execution and read-only delegation; no new network/SSH/SciNet/publication privileges.
- Preserve all explicit configuration and credentials; root-private transaction evidence and exact rollback.
- Defer while jobs/admissions are active; no production changes, research writes, commits or pushes.
- Do not exceed the existing 64-root worker limit; report deferred candidates.

## Review Focus

- Directory replacement/symlink and hardlink races must not cause privileged ACL grants elsewhere.
- Unknown/newer configuration or malformed/duplicate YAML must fail closed.
- Admissions starting between the quiet check and stop must be blocked, not killed; startup schema writes must not deadlock, and crash recovery must verify guard ownership.
- Partial writes, failed startup and interruption must recover exact known config without clobbering edits.
- Repeated scans, explicit overrides, deletion and capacity overflow must remain predictable and idempotent.

### Task 1: Reconciler, wiring and synthetic acceptance

**Files:** Create `scripts/autodiscover-a7dev.py`, `scripts/install-a7dev-autodiscovery.sh`,
`scripts/agentporter-dev-autodiscovery.service`, `scripts/agentporter-dev-autodiscovery.timer`,
`tests/security/test_a7dev_autodiscovery.py` and operator documentation.

- [ ] Write failing tests for filtering, permission parity and preservation of existing explicit roots.
- [ ] Implement a pure reconciliation planner and strict bounded control-file handling.
- [ ] Implement descriptor-pinned ACL enrollment and job-admission barrier; test races and private-path denials on temporary fixtures.
- [ ] Implement managed-state transaction/recovery, no-op behavior, capacity deferral and deletion handling; inject write/start failures in tests.
- [ ] Add immutable installation and timer wiring; preserve acquisition-repair-before-discovery ordering.
- [ ] Run focused security checks, shell syntax and native fixture tests; save a durable worker report.

### Task 2: Independent review and parent verification

- [ ] Review the complete scoped implementation against the spec and privileged boundary.
- [ ] Resolve actionable findings, then rerun affected acceptance checks.
- [ ] Run appropriate regression tests and verify installer hashes and unchanged live state.
- [ ] Record evidence and hand off one concrete sudo-authenticated activation command if authentication remains unavailable.
