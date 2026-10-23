# Jax dispatch and public readiness mismatch

The live failures were authorization denials before Jax launched. A7Dev's journal records `dispatch_agent`, agent `jax`, workspace `Qman`, at 2026-10-21 19:04:17 and 19:04:28 Toronto time, and workspace `m3-poc` at 19:04:29. Each has duration 0.0 and `Operation/workspace outside public-client scope`. No provider execution failure is established by these calls.

The workspace restoration enabled file access and offline execution, but intentionally preserved public delegation only for `cranary` and `agentporter-dev`. Inventory reported runtime confinement/executable readiness without the caller's workspace policy. The MCP SDK hid the ordinary PermissionError behind a generic execution error. Earlier successful Jax provider acceptance does not grant new workspace scope.

## Source correction — not installed

- `src/agentporter/client_policy.py`: public inventory includes the admitted delegation workspaces, the original runtime readiness and the read-only restriction. With a requested workspace, `delegatable` is false if that workspace is denied. No public dispatch grants also makes global `delegatable` false. Workspace inventory/info no longer advertises registry delegation permission that public policy denies. A dispatch denial remains a PermissionError for REST and a safe ToolError for MCP, preserving the reason for the client.
- `src/agentporter/server.py`: MCP supports `list_agents({"workspace_id":"Qman"})`. Without a workspace, the returned scope list explains where the runtime can be requested. Provider quota/execution are explicitly unverified by runtime checks.
- `src/agentporter/rest/routers/agents.py`: the workspace already present in the REST URL now reaches the readiness calculation; an out-of-scope workspace returns 403.
- `src/agentporter/rest/schemas.py` and `docs/agent7-asgard-actions.openapi.json`: retain the scope/readiness fields in REST serialization and the published schema.
- `tests/security/test_public_delegation_readiness.py`: synthetic MCP/REST tests exercise the actual policy/transport path, verify blocked dispatch never reaches the broker, and verify admitted read-only dispatch reaches the mocked broker. No real provider is called.

These fields describe public policy and registry admission. Worker-specific runtime restrictions, authentication, provider quota and execution still apply. Internal authorization and legacy profiles retain their existing behavior. No permission expansion, configuration installation, service restart, account/model change, production change, commit or push was performed.

## Verification

Command (unprivileged, outside the filesystem sandbox because its virtual ancestor permissions trigger the existing trusted-directory check):

```sh
.venv/bin/python -m pytest -q \
  tests/security/test_public_delegation_readiness.py \
  tests/security/test_closeout_client_policy.py \
  tests/unit/test_public_agent_roster.py \
  tests/unit/test_public_action_inventory.py \
  tests/unit/test_delegation_security_metadata.py
```

Result: **40 passed** in 4.71 seconds; one existing Starlette/AnyIO deprecation warning. `git diff --check` passed. Both service states remained `active`; A7Dev still points to immutable v19 `20261021T212000.000019Z`.

Live cause: **executed locally**, journal inspected. Source correction: **unit tests**, including actual synthetic MCP/REST requests. Installed correction and live Qman/m3-poc delegation: **NOT verified / not applied**. Synthetic tests do not establish provider readiness.

## Enabling delegation is a separate owner configuration change

Correcting the report does not grant dispatch. To enable a named project, the owner must approve the exact workspace and read-only delegation scope. The configuration proposal is:

1. In `/var/lib/agentporter-dev/config/public-client-policy.yaml`, add only `dispatch` to the approved workspace's existing operations. For the observed failures the roots are `Qman` → `/home/yeli/repos/Qman` and `m3-poc` → `/home/yeli/m3-agent-poc`; neither is automatically approved by this report.
2. Verify that `/var/lib/agentporter-dev/config/workspaces.yaml` permits execution and agent dispatch for that exact root. Reconcile `/var/lib/agentporter-dev/config/development-runtime.yaml`'s `allowed_workspace_roots`: an approved root must be explicitly present, with `writable: false` sufficient for read-only worker access. The private active runtime file was not read in this diagnosis; its current entries must be checked before any proposed edit is finalized.
3. Preserve private ownership/modes, current bytes and rollback receipts. After checking for active jobs, an authorized operator must load any approved policy change by restarting A7Dev only. Installing the source correction additionally requires the established immutable artifact review/install procedure; do not patch the installed release in place.
4. Validate through public A7Dev: workspace-specific inventory, a read-only Jax task that reads a known file and returns its checksum, job completion/output, protected-path/write/network denials, and the unchanged production service. Do not dispatch a denied workspace through an internal credential to circumvent public policy.

This is a proposal for review, not an executable privileged installer or evidence that these grants have been installed.
