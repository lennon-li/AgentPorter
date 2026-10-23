# Provider-origin compatibility pickup — 2026-10-21

Status: **source verified locally; production readiness remains blocked**. Liz picked up Jax session `01a15b51-7c9c-77f1-a932-ff6c4995a3bd` in the same development checkout. No installation, service restart, commit, push, account change, or provider-route change occurred.

Subsequent user direction prioritizes the existing A7Dev connection. See [live public connection and search acceptance](a7dev-use-now-20261021.md), the later 1,389-test gate, and the inactive v13 package there. The source hashes and 1,379-test receipt below describe the earlier compression repair, before the explicit three-worker production admission change.

## Live baseline — executed locally

Authenticated deploy-info confirmed A7Dev release `20261021T132836.936455Z`, PID `3769995`, matching loaded/disk fingerprint `04a978d2746a88afe79c56af673e6d19850ef24aca9b382becc14426fa8a4fcd`, and `stale=false`. This is v12, without the stricter provider-origin broker. Earlier installed acceptance: [v12 live acceptance](a7dev-v12-live-acceptance-20261021.md).

## Source repair

- Added only `GET https://chatgpt.com/backend-api/wham/accounts/check` for Liz/Prof. Native binary strings and actual diagnostic requests identified this mandatory workspace-discovery route. Tests retain account-write, neighboring-route, other-origin, and hosted-MCP denials.
- Disabled `features.enable_request_compression` in temporary Jax/Liz/Prof profiles under `provider_origin`, including accounts without a canonical config. The installed CLI's isolated `features list` confirms this stable feature defaults to true. Canonical files, model/provider URLs, and account constraints remain unchanged.
- Explicitly rejected non-identity `Content-Encoding` in the provider broker and strict Headroom payload validator. Upstream decoding cannot change the inspected JSON bytes. WebSockets and hosted MCP remain blocked; native Codex falls back to inspected HTTPS.
- Added redacted route-admission decisions to the diagnostic. Its `verified:false` deliberately requires separate native-event review.

## Native evidence — executed locally

Each probe used the existing identity, native executable, actual runtime builder, strict broker, disposable home, and synthetic workspace. The prompt omitted the random file contents. These are unprivileged Bubblewrap compatibility checks, **not installed service-UID confinement or production acceptance**.

| Identity | Reviewed native events | Result directory |
|---|---|---|
| Liz | Local `cat /workspace/ordinary.txt`, exact nonce in tool output and final answer, completed turn | `/tmp/provider-origin-liz-result-a9dp745m` |
| Prof | Local `cat /workspace/ordinary.txt`, exact nonce in tool output and final answer, completed turn | `/tmp/provider-origin-prof-result-zi1o4_7c` |
| Ming | Native `Read`, matching file content and final result, completed turn | `/tmp/provider-origin-ming-result-dr1eh1ah` |
| Jax | Existing Headroom route returned explicit provider usage limit; no completed turn or retry | `/tmp/provider-origin-jax-result-w93bk7k1` |

Parent separately parsed the native read events and matching final responses. Private evidence with output SHA256 values: `/tmp/agentporter-liz-pickup-native-evidence-20261021.json`. Raw diagnostic summaries remain unchanged. Failed discovery/compression probes are not counted as successful execution.

## Verification — unit test / executed locally

Final complete host gate: `bash scripts/verify-development-candidate.sh` — **1,379 tests, 24 subtests, and all standalone verifiers passed**. Log: `/tmp/agentporter-liz-pickup-origin-final-20261021.log`. One existing Starlette/AnyIO deprecation warning remains. `git diff --check` passed. Earlier sandbox-only socket/UID-mapping failures were rerun successfully on the host without weakening checks.

Source SHA256:

- `development.py`: `7ac8f504b4bd5aaf071b90c58af4935037430f985b14062a2cb78403f9c07153`
- `provider_egress.py`: `c7dfe964fe6d1b04f4b7a9d3c3258bbf4aafbc1360af73d08d829947be0bea83`
- `verify-provider-origin-sandbox.py`: `f5427b10e2fdb7a023df488819ce70bfc7b4f64108cde6cfd8b6f1eadba69bb9`

## Outstanding gates — NOT verified

Argie's strict startup remains blocked at `POST /v1internal:writeTrajectoryAcls`. The inherited diagnostic `/tmp/argie-native-policy-result-be2xc_8p/summary.json` recorded only a `trajectoryId` string and prevented upstream execution. Neither that shape nor binary type names establish the server's default ACL behavior. The endpoint remains unadmitted; no cloud ACL write or fabricated acknowledgment was introduced. V12 Argie success used older egress and does not clear this gate.

Jax has a newly observed usage limit. Wei's expired key and Phil's exhausted entitlement remain recorded external conditions; neither was retried here.

Remaining: independent review, provider/search acceptance, immutable receiving/production packages, authorized activation, installed fingerprints/confinement, and live relay/rollback acceptance. These source checks do not clear [production activation gates](production-relay-activation-gates.md). Existing unrelated changes remain preserved; checkout is detached and dirty.
