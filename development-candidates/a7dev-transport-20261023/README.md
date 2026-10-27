# A7Dev Phil transport candidate — NOT activated

Source-only overlay against the exact active development `provider_egress.py` hash in `manifest.json`. No credentials, settings or production code are included. Apply only as part of a separately reviewed development release; do not edit the running `/opt` release in place.

The active rule set cannot CONNECT to `api.github.com`, so native Phil's observed `GET /copilot_internal/user` is denied locally before GitHub can validate its credential. The candidate admits only that exact GET for Phil. Query strings, bodies, other methods, token issuance, repository operations and alternate origins remain denied. The change does not prove that Phil's existing credential is usable once transport is repaired.

TLS hostname verification, public-address checks, method/path admission, stripped proxy headers, bounded response relay, account separation and Bubblewrap launch are unchanged. HTTP upgrade denial is preserved; Codex's successful HTTP fallback is not an authentication defect.

Offline tests use synthetic values and ephemeral synthetic TLS certificates only. No provider request or inference is sent. Run with the installed AgentPorter interpreter:

```bash
PYTHONDONTWRITEBYTECODE=1 /home/yeli/repos/AgentPorter/.venv/bin/python -I -B /home/yeli/repos/AgentPorter/development-candidates/a7dev-transport-20261023/run_offline_tests.py
```

The runner preloads the candidate with active development dependencies before the older harness conftest can import canonical AgentPorter modules. The canonical repo lacks the active development runtime, so a bare combined collection otherwise resolves the wrong dependency tree. Existing harness tests are external evidence inputs, not copied into this candidate.
