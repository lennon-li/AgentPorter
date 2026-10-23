# A7Dev writable local delegation repair

Local journal evidence at 2026-10-22 11:44:54 Toronto shows Liz/Qman rejected before launch with `Public delegation is read-only and cannot publish`. Jax/Qman hit the same policy at 08:07:01. The source gate unconditionally rejected `read_only=false`, even when both project file writes and verified development worker confinement were available.

The repair adds an explicit owner policy operation, `dispatch_write`, alongside existing `write` and `dispatch`. All three must be present and the registry must allow writable delegation. Read-only remains the default. Commit/push booleans remain denied. Actual launches still require the verified development Bubblewrap runtime and exact workspace allowlist. Protected metadata, secrets, network boundaries, per-worker credentials, and cross-workspace confinement retain their existing enforcement.

Runtime/public inventory now reports `public_writable_dispatch_workspaces` separately from read-only readiness. This includes only the intersection of owner scopes, writable registry permissions, and the runtime's exact writable workspace check. Private runtime workspace fields are removed from public results.

## Development-only activation

The source has not been installed and live public writable dispatch has not been validated. First install the reviewed immutable development artifact using the established A7Dev deployment process. Do not patch the installed snapshot in place or alter A7 production.

Run the policy helper as `agentporter-dev`, using explicitly named roots that are already admitted for file writes and delegation:

```sh
sudo -u agentporter-dev /usr/bin/python3 scripts/authorize-a7dev-writable-delegation.py --plan --workspace Qman --workspace agentporter-dev
```

Review its plan hash and exact roots. Stop only `agentporter-development.service`, ensuring zero active jobs/admissions. Apply the identical arguments plus `--apply --expected-plan-sha256 <reviewed hash>`; the helper enforces stopped/quiet state, byte-matching inputs, private file ownership/modes, durable backups, and rollback on failure. It adds `dispatch_write` and enables writes only on those already admitted runtime roots; no roots, registry permissions, HTTPS scopes, credentials, or other runtime settings are added. Protected/unknown projects and overlapping roots are refused. Other project names require their own explicit selection. Restart A7Dev only.

A rollback uses `--rollback --expected-plan-sha256 <same hash>` as the same service account while A7Dev is stopped and quiet. It refuses newer changes and checks the unchanged HTTPS policy. Recovery data stays private at `/var/lib/agentporter-dev/config/writable-delegation-recovery-v1`.

Validate workspace inventory and local file access using an authenticated approved local connection. For each available named identity (Jax, Liz, Prof, Phil, Wei, Ming, Argie), dispatch a minimal authorized marker creation with `read_only=false`; verify job success, exact file contents, and yeli access. Test an atomic replacement too. Repeat read-only write denial, protected metadata and secret denial, sibling-workspace denial, and commit/push rejection. Runtime readiness does not prove provider credentials, quota, or successful model execution. Missing provider availability remains an individual blocker. Do not send credentials to an unverified public destination.

## Verification

Host tests use synthetic credentials and isolated fixture state; no model provider is called. The final focused suite passed 200 checks (one existing Starlette/AnyIO deprecation warning), including real Bubblewrap isolation, existing public scopes, seven named writable broker policies, public MCP/REST scopes, private-policy application/rollback, and read-only defaults. New tests are in `tests/security/test_writable_public_delegation.py`; the development validation gate must run them alongside `tests/unit/test_development_delegation.py` and `tests/security/test_development_runtime.py`. The full candidate gate already runs `tests/`.

Live activation requires operator privileges unavailable to this account. No commit, push, deployment, production service modification, or credential transmission was performed.
