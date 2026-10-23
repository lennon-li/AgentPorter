# Project-access retry preflight

Implemented new service-UID-only bounded preflight. 17 synthetic tests pass. No live private configuration was read or mutated by this worker.

Default/--plan validates old v19 current link, exact previously rolled-back recovery plan SHA 2c4b78429001d4a3f3e5acdfa074d2a0ea5987a3980b04e6d378177d5f9c196c, rolled_back state, all three recovery backup hashes, exact current policy/registry/HTTPS, and current old-version runtime against frozen v19 normalized semantic hash. It verifies 41 admitted projects, five protected projects, Cranary-only HTTPS and unchanged production/network scope. The old-version runtime is intentionally not compared bytewise to the backup, which contains the new release's relocated baseline.

Frozen helper path /opt/agentporter-development/versions/20261021T232414.837654Z/operator-plan/authorize-a7dev-project-delegation.py is opened without following the final symlink, required immutable regular code, read into bounded bytes, checked SHA256 b15410c4ce3962c9233b2947129baec01c7a76e4784a861dc0e3bde8dfbbca2b, then loaded from those exact bytes. Main refuses root and every UID except agentporter-dev.

--preserve-rolled-back-recovery additionally requires stopped service, no lingering cgroup and zero jobs/admissions using the frozen helper. It revalidates all evidence, creates a fresh 0700 exclusive archive parent, and uses Linux renameat2 RENAME_NOREPLACE to move the complete recovery directory to archive/previous. Directory fd fsync makes the rename durable. Existing archives/destinations are never overwritten or deleted. Policy, runtime, registry, credentials, models, account configuration and production are unchanged. Output contains only hashes, paths and scope metadata.

Command: `.venv/bin/python -m pytest -q tests/security/test_project_access_retry_preflight.py`
Result: 17 passed.

Tests cover old/new version normalization, stale policy/registry/HTTPS/runtime/model/link, changed receipt hash/state/scope/network, corrupt backup, quiet/stopped prerequisite, evidence-preserving archive, existing archive and empty destination no-overwrite, and immutable hash-pinned helper loading.

- scripts/preflight-a7dev-project-access-retry.py: `b4e11649a4f2275b2d1dc9ed14bac514629b5ff17bdf5f4e8ffdcfab170ba709`
- tests/security/test_project_access_retry_preflight.py: `11d9ff1f931a19d6aadac9f65865a98cb6663754a2b401856fbe3a68ccda8944`
