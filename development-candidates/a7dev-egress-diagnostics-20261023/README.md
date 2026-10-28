# Development-only provider egress diagnostics — not activated

This overlay targets the exact current active provider relay identified by `manifest.json`. It adds no network origin, operation, credentials, provider refresh, model choice, routing or launch authority.

Only rejected local transport/admission operations and upstream non-2xx response statuses produce warning-level service-journal events. Events contain exactly:

- Fixed event name and configured allowlisted agent alias.
- Static allowlisted host, otherwise `unknown`.
- Allowlisted method and fixed operation label, otherwise `unknown`.
- Fixed processing stage and error-code enum.
- Bounded integer upstream HTTP status when provided, otherwise null.

No raw path, query, request/response headers or bodies, account IDs, auth values, exception text or worker output is logged. The operation parser discards query bytes and returns only fixed labels. Per-launch event emission is capped at 32 with a separate lock. Logging exceptions are swallowed without changing forwarding, response bytes or existing rejection behavior. Successful requests emit no diagnostics.

`upstream_status` means the verified upstream returned the HTTP status; `local_rejection_or_transport_failure` identifies the fixed local processing stage. Neither category proves a particular credential or entitlement issue. Original non-2xx response bytes are forwarded unchanged. TLS verification, model provenance observation, current transport allowlists and confinement remain unchanged.

Offline reproduction:

```bash
PYTHONDONTWRITEBYTECODE=1 /home/yeli/repos/AgentPorter/.venv/bin/python -I -B /home/yeli/repos/AgentPorter/development-candidates/a7dev-egress-diagnostics-20261023/run_offline_tests.py
```

Tests use synthetic metadata, fake in-memory connection objects and the existing offline TLS origin tests. They call no provider and read no authentication files. Candidate-first preloading avoids the older harness conftest resolving the canonical source tree instead of the active development dependencies.

Independent review is required before owner-approved development activation. Do not edit the active `/opt/current` release in place, and do not treat this source-only candidate as a completed Argie live diagnosis.
