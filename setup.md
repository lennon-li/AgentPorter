# AgentPorter → ChatGPT setup on knowhere

Use this runbook when setting up or repairing ChatGPT access to AgentPorter on
`knowhere`. Start with the existing installation checks below. Do not rerun the
one-time installer on a host that already has an immutable release or a
`agentporter-chatgpt.service` unit.

## What is installed here

As checked on 2026-10-24, three user services are active:

| Service | Purpose | Local address |
| --- | --- | --- |
| `agentporter.service` | Main AgentPorter instance | `127.0.0.1:8765` |
| `agentporter-chatgpt.service` | Separate ChatGPT-facing instance | `127.0.0.1:8776/mcp` |
| `agentporter-openai-tunnel.service` | Outbound OpenAI Secure MCP Tunnel | health UI at `127.0.0.1:8080/ui` |

The immutable AgentPorter release was commit
`c73814cbc019faffc1973f93d3e0fc53e5ae9515`; the installed tunnel client
was v0.0.18. Treat these as an observed baseline, not as a version to reinstall.
The tunnel profile is `knowhere-agentporter`. Its tunnel ID is in
`~/.config/tunnel-client/knowhere-agentporter.yaml`; credentials are in private
environment files. Never paste their values into chat, logs, commands, or this
repository.

The dedicated workspace registry is
`~/.config/agentporter-chatgpt/workspaces.yaml`. It exposes:

- `agentporter`: read-only `/home/yeli/repos/AgentPorter`, with read-only Git
  inspection.
- `repos`: read-only `/home/yeli/repos`, including nested folders. Use paths
  relative to that root, such as `AgentPorter/src/agentporter/middleware.py`.

Both workspaces disable execution and worker dispatch. The `repos` workspace
also disables Git actions, artifacts, and local HTTP. AgentPorter's sensitive
path restrictions still apply. File listing defaults to one level of depth;
provide a deeper relative `path` and/or `depth` when browsing a subfolder.

### On a fresh knowhere installation

If the dedicated service and immutable release are **both absent**, review the
[one-time installer](scripts/agentporter-knowhere-install), its five referenced
files in `examples/`, and the [deployment security decision](docs/deployment.md).
The installer is designed for a host that already runs the older main
`agentporter.service`. Its preflight checks that state and the fixed asset
hashes. Run it as the owner from a terminal:

```bash
cd ~/repos/AgentPorter
bash scripts/agentporter-knowhere-install --check
install -d -m 0755 ~/.local/libexec/agentporter-setup
install -m 0555 scripts/agentporter-knowhere-install \
  ~/.local/libexec/agentporter-setup/agentporter-knowhere-install
chmod 0555 ~/.local/libexec/agentporter-setup
~/.local/libexec/agentporter-setup/agentporter-knowhere-install --install
```

It backs up the old main unit, installs a sealed release, starts the dedicated
service, and installs the tunnel unit disabled. If the release or dedicated
service already exists, skip this procedure and continue with the checks below.

## 1. Check the existing installation

Run these read-only commands first:

```bash
cd ~/repos/AgentPorter
systemctl --user is-active agentporter.service agentporter-chatgpt.service agentporter-openai-tunnel.service
~/.local/libexec/agentporter/agentporter-deploy status
~/.local/bin/tunnel-client --version
curl --noproxy '*' -fsS http://127.0.0.1:8080/readyz
```

Expect all three services to be `active`, deploy status to say `ACTIVE`, and
`/readyz` to succeed. `agentporter-deploy status` checks the main service. To
check the dedicated process against its user unit:

```bash
release=~/.local/share/agentporter/current
pid=$(systemctl --user show agentporter-chatgpt.service -p MainPID --value)
"$release/venv/bin/python" -I -m agentporter.cli deploy-check \
  --config-dir ~/.config/agentporter-chatgpt \
  --url http://127.0.0.1:8776 \
  --expect-pid "$pid" --wait 30
```

Expect `ACTIVE`. An unauthenticated request to `/mcp` should return 401. The
OAuth discovery probe should return 404 because this AgentPorter instance uses
an API key, not OAuth:

```bash
curl --noproxy '*' -s -o /dev/null -w 'MCP HTTP %{http_code}\n' http://127.0.0.1:8776/mcp
curl --noproxy '*' -s -o /dev/null -w 'OAuth probe HTTP %{http_code}\n' \
  http://127.0.0.1:8776/.well-known/oauth-protected-resource/mcp
```

## 2. If the tunnel is not configured yet

Only do this section if the profile, credentials, or service are missing. Reuse
an existing suitable tunnel and key. In [Platform tunnel settings](https://platform.openai.com/settings/organization/tunnels),
check that the tunnel belongs to the intended Platform organization and is
associated with the target ChatGPT workspace. Creation needs Tunnels Read +
Manage; running the client and selecting the tunnel need Tunnels Read + Use.
Create a restricted runtime key in [Platform API keys](https://platform.openai.com/settings/organization/api-keys)
if needed. A tunnel ID is an identifier; it does not replace the runtime key.

Check the installed CLI help before changing the profile:

```bash
~/.local/bin/tunnel-client help quickstart
~/.local/bin/tunnel-client init --help
```

For the installed v0.0.18 client, create a missing profile with:

```bash
~/.local/bin/tunnel-client init \
  --sample sample_mcp_remote_no_auth \
  --profile knowhere-agentporter \
  --tunnel-id '<tunnel_id>' \
  --mcp-server-url http://127.0.0.1:8776/mcp \
  --control-plane-api-key-ref env:CONTROL_PLANE_API_KEY
```

Do not rerun `init` over an existing profile without reviewing it. Store the
OpenAI runtime key and the **dedicated** AgentPorter key in
`~/.config/agentporter/openai-tunnel.env` with mode `0600`:

```text
CONTROL_PLANE_API_KEY=<restricted OpenAI runtime key>
AGENTPORTER_API_KEY=<value from ~/.config/agentporter-chatgpt/secrets.env>
```

Enter the real values privately in a local editor. Do not use the key from
`~/.config/agentporter/secrets.env`, which belongs to the main instance. The
[tunnel user unit](examples/agentporter-openai-tunnel.service) injects the
dedicated key via `X-AgentPorter-Key` for discovery and MCP calls.

Validate the profile and start the tunnel service:

```bash
set +x
set -a
. "$HOME/.config/agentporter/openai-tunnel.env"
set +a
export MCP_EXTRA_HEADERS='X-AgentPorter-Key: env:AGENTPORTER_API_KEY'
export MCP_DISCOVERY_EXTRA_HEADERS='X-AgentPorter-Key: env:AGENTPORTER_API_KEY'
~/.local/bin/tunnel-client doctor --profile knowhere-agentporter --explain
unset CONTROL_PLANE_API_KEY AGENTPORTER_API_KEY MCP_EXTRA_HEADERS MCP_DISCOVERY_EXTRA_HEADERS
systemctl --user daemon-reload
systemctl --user enable --now agentporter-openai-tunnel.service
systemctl --user is-active agentporter-openai-tunnel.service
curl --noproxy '*' -fsS http://127.0.0.1:8080/readyz
```

If `doctor` fails, use its named failed check before changing anything else.
The tunnel must stay running for ChatGPT discovery and tool calls.

## 3. Connect and verify in ChatGPT

In ChatGPT on the web, open **Plugins → Add custom MCP server**. Give it a
name, choose **Tunnel**, and select the existing tunnel or enter its tunnel ID.
Choose **No authentication** for the plugin connection: the local tunnel unit
already injects the dedicated AgentPorter key into requests to the private
server. Review the warning, create the plugin, install it, and refresh its tool
list. In a new chat, select the plugin with `@` and call `list_workspaces`, then
`list_files` on workspace `repos` at path `AgentPorter/src/agentporter`.
Setup is complete only when that call succeeds through ChatGPT. Local service
and tunnel health alone do not prove the ChatGPT connection.

## If something fails

| Symptom | Check next |
| --- | --- |
| ChatGPT cannot see the tunnel | Check its ChatGPT workspace association and the operator's Tunnels Use permission in Platform. |
| Tunnel is listed, but tools are missing | Check both services are active, `/readyz`, then rerun `tunnel-client doctor --profile knowhere-agentporter --explain`; refresh plugin tools. |
| `oauth_metadata` fails with 401 | Check that the dedicated service runs commit `c73814c…` or a later release containing the anonymous OAuth discovery probe fix. An unauthenticated `GET /.well-known/oauth-protected-resource/mcp` should return 404. |
| MCP calls return 401 | Check the dedicated key in `openai-tunnel.env` against `agentporter-chatgpt/secrets.env` privately; confirm both `MCP_*_EXTRA_HEADERS` values are in the tunnel unit. |
| `repos` missing | Inspect the dedicated `workspaces.yaml` for the read-only `/home/yeli/repos` entry, restart only `agentporter-chatgpt.service`, then refresh the plugin tool list. |
| Local service is stale or fails deployment verification | Follow [deployment.md](docs/deployment.md); verify the live PID and fingerprint. Keep the main instance and SciNet broker separate. |

For diagnostics without exposing credentials:

```bash
systemctl --user status agentporter-chatgpt.service agentporter-openai-tunnel.service --no-pager
journalctl --user -u agentporter-chatgpt.service -u agentporter-openai-tunnel.service -n 50 --no-pager
```

Review output before sharing it; logs can contain paths or operational details.
The [existing local tunnel guide](docs/openai-tunnel-setup.md) gives additional
background. The [one-time knowhere installer](scripts/agentporter-knowhere-install)
is only for a host without the release and dedicated service. Later code
releases are human-run from the trusted deploy script outside `~/repos`; read
[deployment.md](docs/deployment.md) before deploying.

### Official online references

- [OpenAI Secure MCP Tunnel guide](https://developers.openai.com/api/docs/guides/secure-mcp-tunnels): current tunnel setup, permissions, readiness checks, and troubleshooting.
- [OpenAI custom MCP server guide](https://developers.openai.com/api/docs/guides/custom-mcp-server): current ChatGPT plugin UI, authentication choices, installation, and refresh.
- [OpenAI plugin connection and testing guide](https://developers.openai.com/plugins/deploy/connect-chatgpt): end-to-end test procedure and metadata refresh.
- [Platform tunnel settings](https://platform.openai.com/settings/organization/tunnels): tunnel identity and workspace association.
- [OpenAI tunnel-client releases](https://github.com/openai/tunnel-client/releases) and [onboarding](https://github.com/openai/tunnel-client/blob/master/docs/onboarding.md): version-specific CLI help if the installed client changes.

Use the installed CLI's `--help` and these official pages when an option or
ChatGPT screen differs from this runbook.
