# A7 production and A7Dev — live provider readiness (2026-10-20)

Status: **INCOMPLETE; do not claim 7/7 provider-ready**. These are **real confined agent model invocations**, not installed CLI checks or mock network tests.

| Named agent | Live A7Dev task evidence | Limitation |
|---|---|---|
| Liz | PASS — model produced a response, exit 0 | Confined worker launch and provider channel worked |
| Prof | PASS — model produced a response, exit 0 | Confined worker launch and provider channel worked |
| Argie | PASS — exact `PROVIDER_SMOKE_OK Argie`, exit 0 | Confined worker launch and provider channel worked |
| Jax | FAIL / retrying — Codex model refresh reported connection failed, repeat reconnect | Check Jax-specific `headroom` provider transport host/port/proxy; do **not** switch providers without direction |
| Wei | FAIL — OpenCode Go reports **API key expired** | Replace provisioned source key with a new vendor key, refresh isolated copy |
| Ming | FAIL — Claude reports **OAuth session expired and could not refresh** | Reauthenticate the intended host account, refresh isolated copy |
| Phil | FAIL — GitHub Copilot reports **monthly quota exceeded** | Entitlement/quota reset or a separately authorized licensed identity is needed; copying same key will not remove quota |
 
The development roster reports `delegatable=true` for all seven because it validates installed Linux confinement and credential file existence, **not** provider validity. This flag must not be described as provider-ready.

## Safe credential refresh support

The development provisioner deliberately **keeps existing isolated credentials**, even when host credentials change. Therefore reauthentication on host alone will not update private `agentporter-dev` copies.

A new operator-only helper is staged in `scripts/refresh-development-worker-credentials.py`. It refuses execution unless installed to trusted, root-owned `/usr/local/libexec/agentporter/refresh-development-worker-credentials.py` and invoked using `/usr/bin/python3 -I`. It has a read-only `--check` mode and atomic `--apply --agents` mode. It prints only `current`, `stale_or_absent`, `source_missing`, `refreshed`; `--routes` reports scheme/host/port of Codex provider without query, credentials, keys or URL path. It never starts agents or modifies their provider route. Offline validation: `python3 -B tests/verify_worker_credential_refresh_offline.py` PASS.

**No private credentials were inspected, copied, printed or changed through this chat.** The helper itself is source code only and is NOT installed. An operator must review and install it outside any agent-writable workspace before privileged use. Do not run an agent-writable Python script directly under sudo.

## Production rollout provider gates

1. Require a complete source test gate and independent relay signoff.
2. Install the isolated relay snapshot and production code release under the two separate service identities. Do not silently replace production OAuth/tunnel credentials or the dedicated relay key.
3. For **each agent**, launch a real model-backed smoke through A7Dev and then through A7 production relay, using the *same* named identity, configuration and credentials.
4. Record response, job exit code, provider/model and timing (or precise classified failure); require actual generated content, not only healthy status or an accepted job ID.
5. For an unavailable agent, continue to mark provider access as failed; do not quietly substitute another provider, drop isolation, or advertise a green 7/7 status.
6. Live API failures that only the vendor/account owner can resolve — expired key, expired OAuth grant, or subscription quota — remain hard gates for the affected identity.

No production relay, service, tunnel, privileged install, or credential changes were performed when collecting these provider results.
