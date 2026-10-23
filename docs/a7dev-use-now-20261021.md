# A7Dev usable connection — 2026-10-21

**Later implementation checkpoint:** see [the final v17 handoff](HANDOFF_AGENTPORTER_TO_CHATGPT_2026-10-21.md). Source and frozen-artifact gates each pass 1,439 tests, 24 subtests and all standalone verifiers. v17 is not independently cleared or installed; v12 remains live. The v13/preview receipts below are historical and superseded as rollout targets. Fresh strict-broker native tool checks now pass for Jax, Liz, Prof, Ming and Wei; Argie remains blocked by unresolved ACL-write semantics and Phil remains deferred. These diagnostics do not replace installed service-UID acceptance.

User accepted A7Dev as the temporary entry point. Production rollout is not required for this connection and remains unactivated.

Public MCP endpoint: `https://1xs4h6qn-8876.use.devtunnels.ms/mcp`.

Public Actions schema: `https://1xs4h6qn-8876.use.devtunnels.ms/openapi.json`.

Authentication uses the existing A7Dev API key (`X-AgentPorter-Key` or accepted Bearer authentication), distinct from the production key. Do not paste key material into chat. No credentials were printed during acceptance.

## Current support

- All **53 MCP tool definitions** were enumerated over an authenticated public MCP session. The Actions REST schema exposes 30 operations. Tool exposure does not override workspace permissions or certify every remote action.
- Local files, code execution, Git, jobs, artifacts, and agent-dispatch interfaces are present. Remote Venkata/SciNet permissions remain disabled for the staged development workspaces. Ordinary execution sandboxes have no general network. The owner subsequently enabled [Cranary-only scoped GET/HEAD HTTPS](a7dev-cranary-https-authorization-20261021.md), verified through the public connector; only the fixed broker command forms receive that grant.
- Delegated workers have public HTTPS through their namespace proxy. Parallel Search is an admitted integration for supported worker profiles, limited to `web_search` and `web_fetch`. The stricter future production broker is not deployed in v12.
- Liz, Prof, and Ming passed real native model/tool tasks during this pickup. Argie passed installed v12 acceptance earlier on the same day. Jax's earlier probe hit a provider usage limit; the later strict diagnostic passed on his unchanged Headroom route. Wei's earlier expired-key failure came from an incorrectly selected paid Go route; the owner applied the [Wei-only free-default repair](a7dev-wei-free-repair-20261021.md). A public read-only Wei job now passes with the free default and no caller model override. Phil's exhausted entitlement is intentionally left alone at the owner's request.
- The live roster still reports all seven `delegatable=true` because it verifies OS confinement/executable provisioning, not provider quota. Treat that flag accordingly.

## Executed locally through the public connection

Unauthenticated `/health` and `/openapi.json` both returned HTTP 200 without redirects. An authenticated MCP initialization, `tools/list`, `get_capabilities`, `list_agents`, and `workspace_info` all succeeded. Capability evidence: `/tmp/agentporter-a7dev-public-capabilities-20261021.json`.

Prof job `job_d1d1455f731549d4ad30a90c` completed through the public MCP endpoint. It executed a read-only README SHA256 task in `agentporter-dev`; the returned digest matched the local README. Evidence: `/tmp/agentporter-a7dev-public-task-xkgrektf/`.

Prof job `job_ec2d6b2b6719479ea0788fa8` also completed through that endpoint and returned the official Python pathlib documentation title/URL in response to the approved-search task. This public job interface exposes the final worker text, not the complete native tool trace. Evidence: `/tmp/agentporter-a7dev-public-web-6syr133f/`.

To independently check tool execution, one separate native Prof diagnostic enabled the configured Parallel integration under the stricter source broker. Its native JSON stream records a completed `mcp_tool_call` with `server=parallel-search`, `tool=web_search`, `status=completed`, no error, and actual search results from `docs.python.org`. Evidence: `/tmp/provider-origin-prof-result-zn7503kv/native-output.private`; duration 20.26 seconds, exit 0. This corroborates search functionality without pretending that source diagnostic is installed service-UID acceptance.

## Source preparation retained separately

The final source gate with the explicit Liz/Prof/Ming production admission list and assembled HTTP relay test passed **1,389 tests, 24 subtests, and all standalone verifiers**. Log: `/tmp/agentporter-liz-three-worker-final-20261021.log`. The earlier 1,379 count predates these admission tests.

An inactive v13 archive was prepared and round-trip verified against strict manifests: `/tmp/agentporter-development-candidate-v13.tgz`, SHA256 `d729ddbc10600123bd1f8e28ad2676575bbec35333411391892eca48273af715`, version `20261021T145013.023635Z`. Its runtime selects `provider_origin` and production identities `liz`, `prof`, `ming`. Report: `/tmp/agentporter-development-candidate-v13-review.json`. This is **not activation clearance**, and no v13 launcher or deployment was run. Existing A7Dev remains v12.

The production preview is separate at `/tmp/agentporter-production-candidate-source-v2`. Its initial verification exposed stale copied helper scripts and old candidate-only CONNECT/SNI tests. Helpers were aligned to current source; obsolete tests were preserved under its `docs/historical-transport-review/`, while the replacement TLS authority/body-capability tests remain active. Preview verification is recorded separately; do not confuse it with the source or live A7Dev acceptance above.

The aligned preview's final complete gate passed **1,389 tests, 24 subtests, and all standalone verifiers**, with the same existing deprecation warning. Log: `/tmp/agentporter-production-preview-v2-aligned-verification.log`. An isolated import confirmed its non-editable package lives inside its own venv, all six updated runtime modules match preview source, and no external editable redirect exists. This clears the stale-preview verification failures, not independent review or deployment gates.

Production security/installation gates remain unresolved; Phil remains deferred. Later Jax and Ming recovery evidence is in the v17 handoff. The owner-applied live changes are limited to A7Dev's scoped Cranary HTTPS policy and Wei's free default as documented above. Production, commits, and pushes remain unchanged.
