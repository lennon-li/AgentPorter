# A7Dev smoke repair — combined source candidate

Status: source-only, **not activated**, no real smoke inference executed by this candidate. Scope development gateway only. Production, credentials, settings, account/model routing and OS confinement remain unchanged.

This combines the provenance and Phil transport patches against exactly the five preimages in `manifest.json`, resolving active development source to `/opt/agentporter-development/versions/20261022T224004.423620Z/src`. `candidate.patch` is relative to that source directory. Do not copy one parent overlay over the other; the combined `provider_egress.py` preserves both modifications. No install/restart/deploy command is authorized or included.

## Transport repair

Only Phil gains exact `GET https://api.github.com/copilot_internal/user`, with no query/fragment/body, token issuance, login, repository API, method expansion or other-agent access. Existing origin/TLS verification, payload/tool controls and opaque-WebSocket rejection remain in force. This fixes an independently reproduced local allowlist omission; it does not establish current Copilot credentials or prove live request success.

## Model provenance

The existing host-owned per-launch provider relay observes completed upstream Responses SSE/JSON model fields. Fixed Headroom HTTP Responses can provide the same trusted-runtime evidence. Requests, configured/requested selectors, CLI banners, normal worker logs and assistant JSON never supply model provenance.

A `ProviderModelEvidence` object is created per prepared confined launch, remains entirely in gateway memory and is associated with the generated job ID. It supplies the existing SQLite `actual_model` field only for one unambiguous completed upstream model; requested/configured fields remain separate. No evidence file/socket/environment variable or descriptor enters the worker. No schema migration, dispatch, new collector or Qman authorization is introduced.

Parser supports bounded uncompressed HTTP/1 JSON/SSE and chunking. Invalid, missing, ambiguous, incomplete or oversized input yields unknown without changing forwarding. Only model strings persist. Metadata is committed only when the trusted relay finishes the upstream response; excess bytes or another response after declared/chunked message termination invalidate the observation regardless of network chunk boundaries. This post-review fix prevents a split-input framing discrepancy reproduced by the independent auditor. Original parent candidate files remain frozen for review history.

`actual_model` means the admitted upstream reported a completed response under that model. This does not attest to a provider's private backend. Opaque WebSockets, generic CONNECT, unsupported provider formats, compressed/oversized/missing-model output remain unknown. Active original smoke receipts cannot be backfilled from configured/requested model values. No live repair claim is made until separately authorized development activation and real eligible inference.

## Offline verification

```bash
PYTHONDONTWRITEBYTECODE=1 /home/yeli/repos/AgentPorter/.venv/bin/python \
  /home/yeli/repos/AgentPorter/development-candidates/a7dev-smoke-20261023/run_offline_tests.py
```

**155 passed in 7.56s**: original authority/framing/TLS security suite plus combined Phil regressions, provenance anti-spoof/parser/fragmentation tests, byte-preserving Headroom socket-pair relay, actual development JobManager monitor/SQLite with a local print fixture, and six new post-boundary framing regressions. No model/provider calls, credentials, gateway configuration or live runtime are accessed by these fixtures.

The runner loads the combined overlay modules and fixed active dependency package. It colocates an unchanged copy of canonical anti-spoof tests to avoid Python plugin/module collisions between the two existing conftest trees. Earlier launcher attempts exposed that collection collision; it was fixed in the test harness, not hidden by source/security changes.

## Activation boundary

Independent review must approve this exact combined manifest. Any separately approved development activation must verify preimage hashes, preserve the existing immutable release / confinement / authorization procedures and revalidate live behavior. Do not deploy to production. Missing model evidence remains unknown; provider authentication failures require their own private owner authorization rather than credential copying or account fallback.
