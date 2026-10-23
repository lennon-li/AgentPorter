# A7Dev project access authorization helper

Source implemented; 29 synthetic tests passed. Not installed or applied.

- scripts/authorize-a7dev-project-delegation.py: `b15410c4ce3962c9233b2947129baec01c7a76e4784a861dc0e3bde8dfbbca2b`
- tests/security/test_project_delegation_authorization.py: `f1be68965bbdc3c37df788bcf728b82159477a74af5ac72b6f0f9e676fa6dcd0`

Command: `.venv/bin/python -m pytest -q tests/security/test_project_delegation_authorization.py`
Result: 29 passed in 2.77s.

Helper supports --plan (default), --apply --expected-plan-sha256 HASH, and --rollback --expected-plan-sha256 HASH. It must run only as agentporter-dev, never root.

Apply only after reviewed immutable candidate installation: version relocation changes runtime bytes and therefore plan hash. Obtain a fresh service-UID plan then review its release/scope/hashes before stopped-service apply.

Baseline: exact restored public-policy SHA 97fbbeb9abfb896f4022647218dbc77f80fbfa2bbb3bfea25101756dd4b92043; exact 46 workspace IDs/canonical roots; parsed frozen v19 runtime normalized SHA 308537f5a2da0bf19705fbd5219ffceccd2af517b1a08ebc7318968d3205b863, with only current immutable release prefix relocation permitted. No worker credential files are read.

Changes: add dispatch and offline execution admission for all 41 ordinary projects; preserve five protected public read-only scopes and registry fields; add missing delegated roots with writable:false and downgrade shiny parent to writable:false. Preserve other runtime limits/models/accounts/credentials/network fields, including Wei free model. Existing protected internal runtime admission remains untouched. HTTPS policy is never rewritten; the transaction plan pins its hash.

Stopped-service and zero jobs/admissions are mandatory. Three-file backups and prepared/applied/rolled_back receipts are durable under /var/lib/agentporter-dev/config/project-delegation-recovery-v1. Automatic rollback handles publication errors; explicit rollback handles a crash with mixed before/after bytes. Unknown/newer input state is never overwritten. If interruption occurs before prepared receipt creation, original files have not been mutated and the unused recovery directory needs operator inspection.

Tests cover scope, protected aliases, exact roots, duplicate YAML, malformed permission types, symlink roots, runtime/model/egress drift, approved release relocation, file symlink/hardlink/mode rejection, reviewed-plan requirement, private backup modes, missing/inaccessible workspace directory rejection, idempotent rollback, midwrite failure, crash partial commit, newer-state refusal, unchanged HTTPS and corrupt-backup refusal, active service/jobs/admissions denials.

No sudo, deployment, service restart, commits, pushes, credentials access or other files modified by this worker.
