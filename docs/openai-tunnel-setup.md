# OpenAI Secure MCP Tunnel Setup

This guide explains how to deploy the OpenAI `tunnel-client` alongside an existing AgentPorter instance. It configures the tunnel to automatically inject local Bearer authentication, removing the need to configure local tokens in the OpenAI Platform.

## Prerequisites
* [OpenAI `tunnel-client` binary](https://github.com/openai/tunnel-client/releases) installed (e.g., in `~/bin/tunnel-client`).
* An OpenAI **Tunnel ID** (created in the OpenAI Platform).
* A restricted **OpenAI API Key** with `Tunnels: Read/Use` permissions.
* Your existing local AgentPorter Bearer token.

## 1. Create the Secure Credentials File
Create a protected environment file to store secrets securely without exposing them in logs or systemd files:

```bash
mkdir -p ~/.config/agentporter
touch ~/.config/agentporter/openai-tunnel.env
chmod 600 ~/.config/agentporter/openai-tunnel.env
```

Populate the file with your credentials, making sure to format the local authentication header exactly as shown:

```env
OPENAI_TUNNEL_ID="tunnel_..."
OPENAI_TUNNEL_API_KEY="sk-..."
OPENAI_WORKSPACE_ID="ws_..." # Optional

# The exact HTTP header that will be injected into local MCP requests
AGENTPORTER_AUTH_HEADER="Bearer <YOUR_LOCAL_AGENTPORTER_TOKEN>"
```

## 2. Initialize the Tunnel Profile
Run the connect command once to authenticate with OpenAI and generate the local runtime profile. Replace the `--alias` and `--mcp-server-url` with your desired configuration:

```bash
export $(grep -v '^#' ~/.config/agentporter/openai-tunnel.env | xargs)

tunnel-client runtimes connect \
  --alias my-tunnel \
  --tunnel-id "$OPENAI_TUNNEL_ID" \
  --runtime-api-key env:OPENAI_TUNNEL_API_KEY \
  --workspace-id "$OPENAI_WORKSPACE_ID" \
  --mcp-server-url http://127.0.0.1:8765/mcp
```

After verifying it connects, stop the foreground process:
```bash
tunnel-client runtimes stop my-tunnel
```

## 3. Configure Systemd Persistence
Create a user service to keep the tunnel running in the background and survive reboots. 

Create `~/.config/systemd/user/openai-tunnel.service`:

```ini
[Unit]
Description=OpenAI MCP Tunnel
After=network.target agentporter.service
Wants=agentporter.service

[Service]
Type=simple
EnvironmentFile=%h/.config/agentporter/openai-tunnel.env

# Inject the local bearer token securely via tunnel-client's 'env:' indirection
Environment="MCP_EXTRA_HEADERS=Authorization: env:AGENTPORTER_AUTH_HEADER"
Environment="MCP_DISCOVERY_EXTRA_HEADERS=Authorization: env:AGENTPORTER_AUTH_HEADER"

ExecStart=%h/bin/tunnel-client run --profile-dir %h/.config/tunnel-client --profile my-tunnel
Restart=always
RestartSec=5

[Install]
WantedBy=default.target
```

## 4. Enable and Start
Reload systemd and start the tunnel service:

```bash
systemctl --user daemon-reload
systemctl --user enable --now openai-tunnel.service
```

You can verify the tunnel's health and ensure no authentication errors are occurring by checking the logs:
```bash
journalctl --user -u openai-tunnel.service -f
```
