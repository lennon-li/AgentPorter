# Connect AgentPorter to ChatGPT with a Secure MCP Tunnel

An [OpenAI Secure MCP Tunnel](https://developers.openai.com/api/docs/guides/secure-mcp-tunnels) connects a private AgentPorter MCP server to a ChatGPT workspace. Run `tunnel-client` on a host that can reach the server; the client connects outbound to OpenAI. The existing AgentPorter server and any existing tunnel are not changed by creating an OpenAI tunnel.

## Before you start

- Choose the host, AgentPorter endpoint and workspaces intended for ChatGPT. Verify the running release and its effective permissions. A tunnel carries the server's actual capabilities; it does not make a writable or dispatch-enabled server read-only. A dedicated instance with its own key and explicitly scoped workspaces is a useful option.
- The endpoint must be reachable from the client host, for example `http://127.0.0.1:8776/mcp`. The port and instance are examples; use the actual reviewed endpoint on your host. Do not expose a staging instance as production.
- The client needs outbound HTTPS access to `api.openai.com:443` and connectivity to the MCP endpoint. No inbound Internet port is required. See OpenAI's guide for mTLS and network details.
- Select the intended OpenAI Platform organization and ChatGPT workspace. Creating a tunnel requires organization-level **Tunnels Read** and **Manage**. The restricted runtime key and ChatGPT app operator require **Tunnels Read** and **Use**. The tunnel must be associated with the target ChatGPT workspace, not only the Platform organization.

## Create the OpenAI tunnel

1. Open [Platform tunnel settings](https://platform.openai.com/settings/organization/tunnels), select the intended organization, and create or reuse a tunnel associated with the intended ChatGPT workspace. Record its `tunnel_id`; it is an identifier, not a secret.
2. Create or use a restricted Platform API key with the required tunnel permissions. Keep the key private and enter it locally; do not put it in chat, shell arguments, logs or repository files. Follow your organization's secret-storage practice for persistent operation.
3. From the same Platform settings page, use the link to the [latest tunnel-client release](https://github.com/openai/tunnel-client/releases/latest). Install the appropriate verified binary on the client host and check `tunnel-client help quickstart`. Commands and available flags can vary by version.

## Configure and start the client

The following is an interactive example for an HTTP MCP server using the v0.0.18 profile syntax. Substitute the tunnel ID and endpoint selected above, and verify the installed client's help first. The `read` commands prompt without displaying the keys; they do not store them in shell history.

```bash
read -r -s -p 'OpenAI restricted tunnel API key: ' CONTROL_PLANE_API_KEY; printf '\n'
read -r -s -p 'AgentPorter API key for this instance: ' AGENTPORTER_API_KEY; printf '\n'
export CONTROL_PLANE_API_KEY AGENTPORTER_API_KEY
export MCP_EXTRA_HEADERS='X-AgentPorter-Key: env:AGENTPORTER_API_KEY'
export MCP_DISCOVERY_EXTRA_HEADERS='X-AgentPorter-Key: env:AGENTPORTER_API_KEY'

tunnel-client init \
  --sample sample_mcp_remote_no_auth \
  --profile agentporter \
  --tunnel-id '<tunnel_id>' \
  --mcp-server-url 'http://127.0.0.1:8776/mcp' \
  --control-plane-api-key-ref env:CONTROL_PLANE_API_KEY

tunnel-client doctor --profile agentporter --explain
tunnel-client run --profile agentporter
```

The AgentPorter key and the OpenAI runtime key have different purposes. The example injects the AgentPorter key into both discovery and MCP requests using environment references, as supported by the tested v0.0.18 client. Check your client's help and verify discovery and authenticated calls for other versions. Keep the client running during ChatGPT discovery and use. After stopping it, clear the four variables with `unset CONTROL_PLANE_API_KEY AGENTPORTER_API_KEY MCP_EXTRA_HEADERS MCP_DISCOVERY_EXTRA_HEADERS`.

For unattended operation, configure the host's service manager with an appropriately protected secret source and the same environment references; do not put literal keys in the service command. Verify health, readiness and active polling using the client's local `/healthz`, `/readyz` or `/ui` endpoints. The example [systemd user unit](../examples/agentporter-openai-tunnel.service) is a knowhere-specific reference, not a portable installer.

## Connect ChatGPT and verify

1. Open [ChatGPT Plugins](https://chatgpt.com/plugins), select the plus button, choose **Add custom MCP server**, and choose **Tunnel** under Connection.
2. Select the tunnel or enter its ID, configure the appropriate MCP authentication, review the warning, and create the plugin. If the client injects the AgentPorter key as above, the local MCP endpoint receives that key through the client.
3. Refresh tool discovery and make a safe read-only call such as `list_workspaces` or `get_capabilities`. Check that the returned host and workspace scope are the intended ones. Consider setup verified only after a call succeeds through ChatGPT.

If the tunnel is absent, check its ChatGPT workspace association and the operator's organization-level **Tunnels Use** permission. If discovery fails, confirm the client is running and retry `tunnel-client doctor --profile agentporter --explain`. See the [official troubleshooting guide](https://developers.openai.com/api/docs/guides/secure-mcp-tunnels#troubleshooting) for current guidance.

## Host-specific example: knowhere

The following is the existing knowhere deployment procedure. Its paths, installer and service names are specific to that host and are not prerequisites on other machines.


Before first use from ChatGPT, install a reviewed immutable release following [deployment.md](deployment.md) and verify `agentporter deploy-check` against the live systemd PID and package fingerprint. On knowhere, `agentporter.service` now runs an immutable release on `127.0.0.1:8765`; the dedicated ChatGPT service listens on `127.0.0.1:8776`. The [knowhere service candidate](../examples/agentporter-knowhere.service) preserves the existing host tool path without the editable virtual environment. Back up and compare the installed unit before replacing it on another host. The owner performs the final activation from a terminal, as required by the deployment security decision.

The [knowhere installer](../scripts/agentporter-knowhere-install) automates that owner-run procedure for the reviewed commit `65dbf445bcd16f8e6961a5d5eef4d9f76c084cf8`. Its `--check` mode is read-only. Before `--install`, review the script and the five example files it names, then copy the script into a read-only directory outside all AgentPorter workspaces:

```bash
cd ~/repos/AgentPorter
bash scripts/agentporter-knowhere-install --check
install -d -m 0755 ~/.local/libexec/agentporter-setup
install -m 0555 scripts/agentporter-knowhere-install ~/.local/libexec/agentporter-setup/agentporter-knowhere-install
chmod 0555 ~/.local/libexec/agentporter-setup
~/.local/libexec/agentporter-setup/agentporter-knowhere-install --install
```

The script checks fixed hashes of the five example files before using them. It installs the deployer from that exact Git commit into a separate read-only directory, preserves the old unit as `agentporter.service.pre-release.bak`, builds and tests an immutable release, and verifies it against the live service. If first activation fails, it restores and restarts the old unit. It then starts the dedicated read-only service and verifies its package fingerprint and PID. The OpenAI tunnel service is installed but remains disabled until its private credentials and profile are configured. The M3 gateway and SciNet broker are not restarted.

For later code changes, do not rerun the one-time installer. Review and commit the intended source changes, then have the owner run `~/.local/libexec/agentporter/agentporter-deploy deploy <full-commit-sha>`. That updates and verifies `agentporter.service` on port 8765. Restart `agentporter-chatgpt.service` separately so its process loads the new release, then verify it with the new release's `agentporter deploy-check --config-dir ~/.config/agentporter-chatgpt --url http://127.0.0.1:8776 --expect-pid <dedicated-systemd-MainPID>`. Both services must report `ACTIVE` before testing the tunnel again.

The main `~/.config/agentporter/workspaces.yaml` includes a writable `/home/yeli/repos` registration. The dedicated ChatGPT instance keeps its own key and permissions. Its `agentporter` workspace remains read-only, and its `repos` workspace grants read-only access under `/home/yeli/repos`, including nested folders. Execution, worker dispatch, artifacts, Git actions on the parent directory, and loopback HTTP remain disabled for `repos`. Sensitive paths are still blocked by AgentPorter. An isolated instance has its own config, state, API key, and loopback port while using the same immutable package release.

The [dedicated service](../examples/agentporter-chatgpt.service), [server config](../examples/knowhere-chatgpt-config.yaml), and [workspace registry](../examples/knowhere-chatgpt-workspaces.yaml) are reviewed starting points installed by the script. On first startup, AgentPorter creates a separate `secrets.env` in `~/.config/agentporter-chatgpt/`. Copy only that dedicated key into the tunnel's private environment file; keep the existing 8765 instance and M3 configuration separate.

Check `systemctl --user is-active agentporter-chatgpt.service`, a healthy `http://127.0.0.1:8776/health`, and the authenticated `/api/v1/server/deploy-info` result before connecting the tunnel. Its PID, path, and fingerprint must match the dedicated unit and active `RELEASE.json`.

Current source deliberately blocks worker delegation and remote Git publication. A ChatGPT connection does not change those limits.
