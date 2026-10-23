# Binary acquisition tool discovery — live public verification

The running A7Dev v19 already registers and exposes `https_download`. Authenticated public and literal-loopback MCP `tools/list` returned the same tool descriptor with required `workspace_id`, `url`, `filename` and optional `expected_sha256`, `max_bytes` (default 16,777,216), `timeout_seconds` (default 60). Both endpoints reached PID 530299, loaded/disk fingerprint `2a41380b67529e5bb27fa3e00d7a84ced0946989879b3948a97c25f5eeee6ac7`, not stale.

No server activation, code change, restart, credential change or network expansion was needed for this tool. ChatGPT's actual connection metadata was not accessible in this Codex session. The available Plugin Management integration returned no `a7dev` plugin match and supplies no custom-MCP refresh operation. The remaining discrepancy is consistent with stale or disabled client registration; it does not establish which client-side condition applies.

## Executed acceptance

Command: `.venv/bin/python scripts/verify-a7dev-binary-discovery.py` (unprivileged native execution).

- Public `https_download` URL: `https://packagemanager.posit.co/cran/2022-06-30/src/contrib/PACKAGES.gz`.
- HTTP **200**, **776,874 bytes**, retrieved `2026-10-21T23:30:11.757788+00:00`.
- Saved exclusively to `data-raw/cran-history/reports/2026-10-21-authorized-acquisition/downloads/PACKAGES-2022-06-30-tool-discovery-737f0fbf30681d97.gz`.
- SHA256 **`d2cd86e52af94510adf4e9aed96d4cc7b4172a5a93c3ba0e0094569bf93e4c52`**; the saved file was independently rehashed by offline public `exec_run` and matched the receipt.
- Bounded gzip expansion/CRC validation passed: 3,540,372 bytes, SHA256 `71d1c54a6c2e636732227fa2501c9d25b665ab66a6becd5b1f55dd20be2ce077`, 18,339 package records. No population selection or research consumer was run.
- Seven live denial calls passed: limit above 16 MiB, timeout above 60 seconds, unapproved hostname, loopback IP, wrong workspace, destination traversal and wrong expected checksum. Failed requests did not become authorized acquisitions.
- The first snapshot fetch had no independently supplied upstream checksum (`expected_sha256_verified=false`). Its receipt plus saved-byte and gzip verification prove transfer/file integrity, not independent publisher identity or historical population completeness. Training eligibility and historical-identity flags remain false.

Evidence: [public/local discovery, exact schemas, payloads and receipts](evidence/a7dev-binary-discovery-20261021/public-local-discovery-and-download.json), [verification log](evidence/a7dev-binary-discovery-20261021/verification.log), [checksum index](evidence/a7dev-binary-discovery-20261021/sha256.json).

## Required ChatGPT account action

Open the existing **a7dev** custom connection in ChatGPT's Apps/Plugins settings, select **Refresh**, confirm `https_download` is listed/enabled, then start a new conversation with a7dev selected. Ensure that connection points to `https://1xs4h6qn-8876.use.devtunnels.ms/mcp`. This is the [official custom MCP metadata refresh procedure](https://developers.openai.com/plugins/deploy/connect-chatgpt#refresh-metadata); app details also support managing enabled tools ([official guide](https://developers.openai.com/api/docs/guides/custom-mcp-server)). No API key should be pasted into chat.

After refreshing, ask ChatGPT to invoke `a7dev.https_download` with the payload below. Use a new filename; existing acquisitions are never overwritten. The expected checksum is now pinned to this verified receipt, so a changed publisher response must fail rather than silently replace evidence.

```json
{
  "workspace_id": "cranary",
  "url": "https://packagemanager.posit.co/cran/2022-06-30/src/contrib/PACKAGES.gz",
  "filename": "PACKAGES-2022-06-30-chatgpt-verification.gz",
  "expected_sha256": "d2cd86e52af94510adf4e9aed96d4cc7b4172a5a93c3ba0e0094569bf93e4c52",
  "max_bytes": 16777216,
  "timeout_seconds": 60
}
```

Server discovery and invocation: **executed locally through public MCP, PASS**. Refreshing the actual ChatGPT account and invoking its imported native tool: **NOT verified; requires that account action**. No claim of end-to-end ChatGPT registration success is made.

Only new quarantined acquisition bytes were saved as explicitly requested. Existing research files/frozen datasets were not changed. No training, commit, push, production modification, unrestricted networking or redirect allowance occurred.
