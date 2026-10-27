# ChatGPT access to AgentPorter on knowhere

Use an [OpenAI Secure MCP Tunnel](https://developers.openai.com/api/docs/guides/secure-mcp-tunnels) to connect a private AgentPorter MCP endpoint to a ChatGPT custom MCP plugin. AgentPorter stays bound to `127.0.0.1`; the tunnel client makes outbound HTTPS requests to OpenAI. ChatGPT plugin access and Platform tunnel permissions are separate.

## Knowhere status and scope

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

## OpenAI prerequisites

1. In [Platform tunnel settings](https://platform.openai.com/settings/organization/tunnels), create or reuse a tunnel associated with the intended ChatGPT workspace. The creator needs Tunnels Read + Manage; the runtime key and plugin operator need Tunnels Read + Use.
2. Create a restricted runtime key with Tunnels Read + Use. Store it in a private local file; never put it in a command argument, repository, or transcript.
3. Knowhere already has the checksum-verified `tunnel-client` v0.0.18 in `~/.local/bin/`. Run `tunnel-client help quickstart` and use the installed binary's help for command syntax. For future upgrades, use the release linked in the [official guide](https://developers.openai.com/api/docs/guides/secure-mcp-tunnels).

Knowhere's prepared client was v0.0.18. These commands match that version; recheck help after upgrading.

## Local profile and authentication

Point the profile at the dedicated ChatGPT-facing AgentPorter loopback endpoint. `8776` is an example port; check that it is free before using it. The `tunnel_id` is an identifier, not the runtime key.

```bash
tunnel-client init \
  --sample sample_mcp_remote_no_auth \
  --profile knowhere-agentporter \
  --tunnel-id '<tunnel_id>' \
  --mcp-server-url http://127.0.0.1:8776/mcp \
  --control-plane-api-key-ref env:CONTROL_PLANE_API_KEY
```

Create `~/.config/agentporter/openai-tunnel.env` with mode `0600` from your terminal. Put only these two values in it; copy the AgentPorter key from `~/.config/agentporter-chatgpt/secrets.env` after the installer has started that service:

```text
CONTROL_PLANE_API_KEY=<restricted OpenAI runtime key>
AGENTPORTER_API_KEY=<dedicated agentporter-chatgpt key>
```

AgentPorter accepts `X-AgentPorter-Key`; `tunnel-client` v0.0.18 can inject that header for both MCP discovery and calls via `env:` references. Do not reuse the existing `~/.config/agentporter/secrets.env`, which also contains an unrelated M3 key. Do not paste either key into chat, commands, logs, or the repository.

The [example user unit](../examples/agentporter-openai-tunnel.service) loads that private file and injects the header. The installer copies it without enabling it. Its `ExecStart` expects `tunnel-client` at `~/.local/bin/tunnel-client`.

```bash
set -a
. ~/.config/agentporter/openai-tunnel.env
set +a
export MCP_EXTRA_HEADERS='X-AgentPorter-Key: env:AGENTPORTER_API_KEY'
export MCP_DISCOVERY_EXTRA_HEADERS='X-AgentPorter-Key: env:AGENTPORTER_API_KEY'
tunnel-client doctor --profile knowhere-agentporter --explain
unset CONTROL_PLANE_API_KEY AGENTPORTER_API_KEY MCP_EXTRA_HEADERS MCP_DISCOVERY_EXTRA_HEADERS
systemctl --user daemon-reload
systemctl --user enable --now agentporter-openai-tunnel.service
systemctl --user is-active agentporter-openai-tunnel.service
```

The client exposes loopback `/healthz`, `/readyz`, and `/ui`. Check that it is ready and polling before configuring ChatGPT. Keep the tunnel service running for discovery and tool calls. The tunnel must reach `api.openai.com:443` and the local AgentPorter endpoint; no inbound internet port is needed.

## Connect ChatGPT

In ChatGPT on the web, open **Plugins → Add custom MCP server**, choose **Tunnel**, select the associated tunnel, and configure the plugin's authentication. With the local key injected by `tunnel-client`, the plugin itself uses no authentication to the tunnel endpoint; the tunnel still uses its restricted runtime key. Refresh the discovered tools and make a read-only `list_workspaces` or `get_capabilities` call. Only report access as working after that call succeeds through ChatGPT.

ChatGPT custom MCP plugin availability depends on the target workspace's permissions. The official [custom MCP server guide](https://developers.openai.com/api/docs/guides/custom-mcp-server) describes the current UI and supported authentication modes.
