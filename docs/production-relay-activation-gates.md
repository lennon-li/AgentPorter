# Production A7 → isolated A7Dev delegation relay

State: **SOURCE STAGED; NOT INSTALLED OR ACTIVE**.

Verification evidence, 2026-10-20 (operator-run in Asgard source checkout): **1,049 pytest passed, 24 subtests passed, one non-blocking Starlette deprecation warning, 65 offline HTTPS tests passed, integration/offline regression and production relay offline verifier passed; final line PASS: complete development candidate verification.** This proves the checkout tests pass, not that immutable installed gateways contain the candidate. Independent relay signoff and live separate-UID deployment checks remain pending. The old production gateway remains authoritative for all non-agent tools. No production UID may launch a model worker locally.

## Boundaries

- A7 production 127.0.0.1:8765: authenticated public MCP/REST remains unchanged. When (and only when) a protected upstream config exists, its seven named worker calls forward to the narrow loopback delegation route on 127.0.0.1:8876.
- A7Dev 127.0.0.1:8876: separately owned by agentporter-dev, constructs/validates kernel-enforced Bubblewrap worker launch and isolated provider credentials. The ordinary development API key is **not** the relay credential.
- Internal path POST /internal/delegation/v1, fixed body shape `{operation,args}`, operation allowlist: list_agents, workspace_info, dispatch_agent, lookup_dispatch, job_status, job_output, job_result. No generic HTTP, shell, Git, filesystem, executable, environment or URL parameters.
- Dedicated Bearer credential is only valid on the relay path, with a verified local socket peer. General production and development API keys must differ from that key. Relay credentials do not grant any ordinary REST/MCP tool privileges.
- Only owner-enumerated workspace IDs with **matching absolute roots on both gateways** and approved agent_dispatch can be used. Worker identities limited to the seven built-ins.
- This first release **only permits read-only agent work**. Commits, pushes and local PID-based job cancellation are denied. Writable tasks require a separate independently audited grant.
- SQL job ownership survives restarts; idempotent request IDs are reserved before worker launch; unknown IDs rejected. SQLite serializes reservations across processes, with a three-outstanding-job cap. Missing verified terminal evidence **never** frees a slot.
- HTTPS metadata broker is separate; this relay does not grant it to production or broaden outgoing network access.

## Owner-installed private configuration (not yet installed)

Generate **one fresh cryptographically random token**, 32+ bytes, keep it out of the project checkout and ChatGPT. Install TWO *private copies* containing the same token:

1. Production: `/home/yeli/.config/agentporter/delegation-relay.key`, owner yeli, mode 0600.
2. Development: `/var/lib/agentporter-dev/config/delegation-relay.key`, owner agentporter-dev, mode 0600.

Both parent directory chains must be owner-trusted. Do not reuse the production A7 API key or A7Dev API key.

Add a private production `/home/yeli/.config/agentporter/delegation-upstream.yaml` owned by yeli, mode 0600. Example **choose only the needed workspaces**:

```yaml
version: 1
host: 127.0.0.1
port: 8876
workspaces:
  - PAGe
  - cranary
```

Add private development `/var/lib/agentporter-dev/config/delegation-relay-scope.yaml`, owned by agentporter-dev, mode 0600. Explicitly pin the dev workspace roots and grant no others:

```yaml
version: 1
workspaces:
  PAGe: /home/yeli/repos/PAGe
  cranary: /home/yeli/repos/cranary
```

These are policy examples, not authorization to activate. The operator should independently confirm paths and scope. If production registry roots differ from the development registry, delegation is denied.

## Last independent review and follow-up

Liz completed a focused independent review and confirmed fixes for seven earlier relay findings. She identified an additional capacity-exhaustion case: policy-rejected dispatches left active, unbound reservations, and the `output_limit_exceeded` job status was not treated as terminal. Both were patched after the 1,049-test run. The new offline and unit regression suites cover rejection-capacity reclamation while keeping spent retry tokens. **Therefore the 1,049-test pass predates the latest fixes; rerun full Python 3.13 verification before activation.**

The longer Prof re-audit remains pending. This source tree is NOT approved for production solely from the earlier passing test receipt.

## Required pre-activation gates

1. Full **post-change** project pytest/security suite under host Python 3.13. Run `bash scripts/verify-development-candidate.sh`. The pre-relay 1,038-test result is not post-relay acceptance.
2. Independent Prof security signoff on code, authentication separation, immutable deployment and all relay policy files, including assembled FastAPI ASGI route, key crossover, response size and cross-process tests.
3. Immutable development snapshot rebuild by owner and verify loaded code fingerprint; development startup should remain separate UID and verified Bubblewrap.
4. Independently reviewed production immutable release deployment of exact code pin, using the existing trusted operator script; no agent-writable checkout should ever become production executable source. Preserve existing production state/tunnels. Rollback if health or auth/confinement checks fail.
5. Install owner-controlled scope/token files, restart ONLY the intended services through the owner-approved deployment path. Verify production and development credentials are different, and relay source bind remains loopback.
6. Negative live tests: regular API keys denied on relay; relay key denied on regular tools; disallowed agent/workspace; mismatched path; write/commit/push/cancel; unrelated job reference; concurrent dispatch limit; network/worker failure with zero unconfined local fallback.
7. Positive live test: production A7 `list_agents` and a single read-only Prof job; `job_status`, `job_output` and `job_result` must resolve through the opaque durable production job ID. Check production PID fingerprint and no local model subprocess.
8. Validate provider-backed execution individually. Provider results so far: Prof, Liz and Argie have completed real calls; Ming completed an earlier call but later failed with expired OAuth; Jax hit connectivity errors, Wei has an expired API key, and Phil has exhausted monthly quota. These provider failures do not justify opening a production bypass.

## Known limitations
- Relay jobs are read-only, limited to the explicit overlapping workspace list.
- Safe cancellation is disabled pending process-handle/cgroup control to prevent stale PID/PGID signalling.
- An uncertain dispatch response is reported with a persistent `rjob_` identifier; status recovery checks the durable receiving-side request ID. The caller must not resend a new independent task until recovering the prior outcome.
- A pending reservation with unknown outcome consumes a capacity slot, intentionally failing closed rather than fabricating a successful or safe completion. Operator reconciliation/cleanup needs a separately reviewed mechanism.
- Relay authentication and scope installation require operator authority, and production deployment must remain an owner-run controlled action. A7Dev's sandbox cannot modify protected production service files.
- Do not advertise `delegatable=true` as proof of working provider credentials; separate provider availability smoke checks are required.

No privileged installation, commit, push, or service restart is performed by this document.
