# A7Dev provenance repair candidate — not activated

This overlay targets the exact active development source identified in `manifest.json`. It does not edit `/opt`, change gateway credentials or routes, modify production, add network permissions, or rerun model inference. Apply only after independent review and separate owner authorization for development activation. All files are source/test artifacts, not a credential or transcript snapshot.

## Observed cause

Both canonical and active `provenance.extract_actual_model` unconditionally return `unknown`. That is deliberate spoof prevention: worker stdout/stderr contain arbitrary worker text. Codex banners, configured/requested selectors and assistant-provided JSON cannot establish confirmed actual model. Existing receipts therefore cannot gain verified actual-model data retrospectively unless independently retained provider/runtime metadata exists.

## Minimal repair

The already host-owned, per-job provider relay can read the authenticated upstream Responses HTTP response; the existing fixed Headroom relay can read its trusted local upstream response. A new in-memory `ProviderModelEvidence` records only `response.completed.response.model` (or completed non-streaming response `model`). It never reads model data from a request, selection config, CLI banner, worker output, billing or quota response.

`DevelopmentRuntime._build` constructs one observer for one prepared launch. Its object stays in the gateway process, outside Bubblewrap; no evidence file, socket, environment value or descriptor enters the worker. The same prepared object is registered under the generated job ID by `JobManager`. On job completion/cleanup, only that job's observer supplies its actual-model field. Log paths remain ignored and arbitrary evidence-like objects are rejected. Existing DB column/schema is reused. Multiple distinct completed model IDs return `unknown` instead of silently selecting one.

Existing TLS verification, endpoint/request validation, process resource envelopes, cleanup and all forwarding bytes remain unchanged. This is a best-effort observer, not a new provider request or transport. The parser supports HTTP/1 JSON/SSE, split transport reads and chunked bodies, rejects conflicting duplicate fields/headers, compression, malformed framing, incomplete messages, invalid/oversized model/event fields. Raw provider content is not persisted. SSE event memory is bounded to 256KiB, header to 8KiB; only model strings survive. Parser failure leaves provenance unknown and does not change relay or job outcome.

## Evidence strength / limitations

The field means the existing admitted upstream reported this model on a completed inference response. It does not cryptographically attest a provider's private backend. Headroom is an existing trusted local upstream, and could itself relay a provider model ID. Neither a request header nor a completed task alone proves actual model.

Opaque WebSockets, generic public CONNECT, non-Responses provider APIs, missing model fields, compressed/oversized messages and missing completion events remain unknown. No actual-model claim for Ming, Phil, Argie or Wei is added without their own trusted format. No inferred selector fallback, model switch or account switch occurs. The observer alone does not prove OS confinement; it uses the already existing prepared confined path.

No live source changes or inference were performed by this worker. Active gateway still returns unknown until a separately approved activation and eligible normal inference capture; previously completed original receipts cannot be repaired by guessing.

## Tests

```bash
PYTHONDONTWRITEBYTECODE=1 /home/yeli/repos/AgentPorter/.venv/bin/python -m pytest -q -p no:cacheprovider \
  /home/yeli/repos/AgentPorter/development-candidates/a7dev-provenance-20261023/tests
```

30 passed. Includes 27 adversarial parser cases and three wiring/storage tests. The existing Headroom byte relay runs against local socket pairs and preserves bytes while observing only upstream bytes. The actual development JobManager monitor runs synthetic local print processes: its SQLite result uses the job-bound reported model while keeping requested/configured models separate, and ignores spoofed worker model JSON. These are offline fixtures, not live gateway or provider authentication tests. Active development imports are used only as dependency source; test no gateway config, provider auth or network is opened.

Review preimage hashes before any merge. The sibling transport overlay modifies a separate allowlist hunk in `provider_egress.py`; merge the reviewed hunks against the same baseline, never overwrite the other repair or live source wholesale. `candidate.patch` is relative to the active `src` directory. No command in this file deploys anything.
