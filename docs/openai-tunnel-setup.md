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

For unattended operation, configure the host's service manager with an appropriately protected secret source and the same environment references; do not put literal keys in the service command. Verify health, readiness and active polling using the client's local `/healthz`, `/readyz` or `/ui` endpoints. The example [systemd user unit](../examples/agentporter-openai-tunnel.service) is a workstation-specific reference, not a portable installer.

## Connect ChatGPT and verify

1. Open [ChatGPT Plugins](https://chatgpt.com/plugins), select the plus button, choose **Add custom MCP server**, and choose **Tunnel** under Connection.
2. Select the tunnel or enter its ID, configure the appropriate MCP authentication, review the warning, and create the plugin. If the client injects the AgentPorter key as above, the local MCP endpoint receives that key through the client.
3. Refresh tool discovery and make a safe read-only call such as `list_workspaces` or `get_capabilities`. Check that the returned host and workspace scope are the intended ones. Consider setup verified only after a call succeeds through ChatGPT.

If the tunnel is absent, check its ChatGPT workspace association and the operator's organization-level **Tunnels Use** permission. If discovery fails, confirm the client is running and retry `tunnel-client doctor --profile agentporter --explain`. See the [official troubleshooting guide](https://developers.openai.com/api/docs/guides/secure-mcp-tunnels#troubleshooting) for current guidance.

## Dedicated instance

Use the [dedicated service example](../examples/agentporter-chatgpt.service) with a separate configuration directory, state directory, API key, and loopback port. Define only the workspace permissions needed by the connected client. Start with the generic [configuration](../examples/config.example.yaml) and [workspace registry](../examples/workspaces.example.yaml), then follow the [deployment guide](deployment.md) to install and verify an immutable release.

Configure the [tunnel service example](../examples/agentporter-openai-tunnel.service) with a private environment file and the profile created above. Before connecting ChatGPT, verify the dedicated instance's health, package fingerprint and PID using `agentporter deploy-check` with its configuration directory, URL and expected service PID.
