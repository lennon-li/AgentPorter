# ChatGPT → A7Dev → Asgard connection audit

Audit date: 2026-10-22. Read-only inspection of live processes, configuration,
installed code, existing logs, and harmless HTTP/tool requests. No services,
configuration, permissions, or credentials were changed. This report is the
requested output; no credential values or credential hashes are included.

## Finding: why “No authentication” still works

**The live OpenAI development tunnel injects the AgentPorter authorization header
locally.** The gateway is not unauthenticated. The ChatGPT connection does not
need to supply this local credential for that tunnel path to work.

The running `openai-tunnel-development.service` has both settings below:

```ini
EnvironmentFile=/home/yeli/.config/agentporter/openai-tunnel-development.env
Environment="MCP_EXTRA_HEADERS=Authorization: env:AGENTPORTER_DEV_AUTH_HEADER"
Environment="MCP_DISCOVERY_EXTRA_HEADERS=Authorization: env:AGENTPORTER_DEV_AUTH_HEADER"
```

The environment file contains `AGENTPORTER_DEV_AUTH_HEADER` in Bearer format.
In-memory comparisons confirmed the running process has the same value as that
file. HTTP tests confirmed that value is accepted by the live gateway. The
value was never printed or written to the report.

“No authentication” in the reported ChatGPT UI is therefore consistent with
**no connector-supplied upstream credential**, while the local tunnel still
authenticates its requests to AgentPorter. It does not mean every downstream
hop is anonymous. The exact remote UI configuration is not exposed to this
audit; the header-injection mechanism itself is verified locally, not inferred
merely from successful tools.

The previous explanation that the A7Dev key must be saved in the ChatGPT
connection was unsupported and is corrected by this finding.

## Connection diagram

```text
Observed A7Dev tool transport

ChatGPT A7Dev tool/connection
  |  OpenAI-side tool routing (remote connector definition not inspectable)
  v
OpenAI MCP tunnel service/control plane: https://api.openai.com
  ^  outbound tunnel-client polling/response transport
  |  authenticated using OPENAI_TUNNEL_API_KEY
  v
Asgard: openai-tunnel-development.service [user yeli; PID 2239147]
  /home/yeli/bin/tunnel-client run
    --profile-dir /home/yeli/.config/tunnel-client-development
    --profile asgard-dev
  |  inject Authorization from env:AGENTPORTER_DEV_AUTH_HEADER
  v
http://127.0.0.1:8876/mcp
  |
  v
agentporter-development.service [user agentporter-dev; PID 1757595]
  |  API-key middleware -> authenticated public-client principal
  |  workspace/action policy -> tool-specific checks
  v
Allowed files / Git / offline Bubblewrap execution / scoped worker dispatch

Separate parallel ingress (not an extra hop in the observed tool path)

HTTPS client with caller-supplied AgentPorter key
  |
  v
https://1xs4h6qn-8876.use.devtunnels.ms/mcp
  |  Microsoft Dev Tunnels; anonymous connect permission
  v
Asgard: agentporter-development-tunnel.service [user yeli; PID 1684510]
  /home/yeli/bin/devtunnel host agentporter-development.use
  |
  v
Same AgentPorter listener at 127.0.0.1:8876
```

**Both mechanisms are active.** The public Microsoft URL is not the upstream
configured in the OpenAI tunnel: that upstream is the direct loopback `/mcp`
URL. They must not be conflated. The separate `asgard-tunnel.service` runs
`devtunnel host asgard-gateway`; it is not the development tunnel identified
above. A separate production OpenAI profile targets port 8765, not 8876.

## What happens during an A7Dev invocation

1. ChatGPT invokes the A7Dev tool through its connected tool infrastructure.
   The remote connector definition/account binding is not locally inspectable.
2. The OpenAI development tunnel receives a command through its control-plane
   transport. Its profile uses `https://api.openai.com` and
   `control_plane.api_key: env:OPENAI_TUNNEL_API_KEY`.
3. `tunnel-client` forwards the command to its configured MCP channel `main` at
   `http://127.0.0.1:8876/mcp`, injecting the locally configured Authorization
   header. The discovery header is configured separately with the same reference.
4. The listener is the system `agentporter-development.service`, running
   `/opt/agentporter-development/current/venv/bin/python -I -m agentporter.cli
   serve --config-dir /var/lib/agentporter-dev/config --host 127.0.0.1 --port 8876`.
5. Installed middleware applies host, rate, payload, and authentication checks.
   It accepts the configured key header, optional legacy header, or Authorization
   fallback. `verify_api_key()` strips a Bearer prefix and compares key bytes
   with `hmac.compare_digest`. Missing/incorrect keys return HTTP 401.
6. Successful public authentication establishes the public-client principal.
   `PublicClientPolicy.check()` checks the requested workspace and operation;
   tool implementations then enforce their own path, execution, Git, network,
   and worker restrictions. Possession of the key does not bypass those policies.
7. The result returns through the OpenAI tunnel infrastructure to ChatGPT.

## Credential locations and boundaries

| Hop | Credential / mechanism | Verified storage or reference |
| --- | --- | --- |
| ChatGPT → OpenAI tool infrastructure | Existing ChatGPT connection/account context; user reports “No authentication” | Remote connector settings and any remote credential store were not exposed to this audit. No saved ChatGPT API key is assumed. |
| Local OpenAI tunnel → OpenAI control plane | `OPENAI_TUNNEL_API_KEY` | `/home/yeli/.config/agentporter/openai-tunnel-development.env`, mode 0600, owner yeli; running process contains the variable; profile references it through `env:`. Remote key scopes were not inspected. |
| OpenAI tunnel → local AgentPorter | Injected `Authorization` using `AGENTPORTER_DEV_AUTH_HEADER` | Same protected environment file; running-process/file equality verified in memory. This credential differs from the OpenAI control-plane key. |
| Microsoft public URL → AgentPorter | Caller must supply a valid AgentPorter key | Microsoft tunnel allows anonymous connections. Its hosting process authenticates separately to Microsoft; hosting-account credential details were not inspected. No AgentPorter-header injection is configured in this tunnel unit. |
| AgentPorter expected key | Loader prefers `AGENTPORTER_API_KEY`, otherwise `AGENTPORTER_API_KEY=` or legacy `API_KEY=` in `secrets.env` | Service config directory is `/var/lib/agentporter-dev/config`; expected file is `/var/lib/agentporter-dev/config/secrets.env`. No API-key override appears in the unit's configured environment. Direct gateway-file/process-environment inspection was permission denied, so the loaded key's exact source and that file's current mode were not independently read. Installed loader attempts mode 0600. |

The profile `/home/yeli/.config/tunnel-client-development/asgard-dev.yaml` is also
mode 0600, owner yeli. `env:` indirection keeps the local Bearer value out of
the unit file and command-line arguments. It remains present in the tunnel's
process environment and is accessible to sufficiently privileged local users.

## Live evidence

- **Services/processes:** user tunnel units above are active. System gateway
  unit is active. Process executable/arguments match the stated tunnel clients.
  `ss` shows the listener bound to `127.0.0.1:8876`, not a public interface.
- **Microsoft forwarding:** `devtunnel show agentporter-development.use`
  reports one hosted HTTP port, 8876, the stated HTTPS URL, and access control
  `{+Anonymous [connect]}`.
- **Instance identity:** `current` resolves to
  `/opt/agentporter-development/versions/20261022T015212.581522Z`.
  The A7Dev `server_deploy_info` tool and authenticated loopback/public REST
  requests all identify PID **1757595**. Loaded/disk fingerprint:
  `3f5b472115d7ac1ee147c29279b532bf175bc63891846a8b17ec94429a3ed099`;
  the tool reports `stale: false`.
- **Controlled transport correlation:** one `a7dev.server_deploy_info` call ran
  from **14:44:21.440Z to 14:44:29.333Z**. Existing OpenAI development tunnel log
  `/home/yeli/.local/state/tunnel-client/logs/asgard-dev.log` grew from 2104 to
  2105 decoded events, adding exactly one
  `dispatcher forwarded command to MCP server` event at
  **10:44:29.139174722-04:00** (14:44:29.139Z), inside the call window.
  This supports the observed OpenAI tunnel route; no remote connector export or
  packet capture was available to independently inspect the cloud-side hop.
- **Runtime:** `tunnel-client` reports version
  `0.0.14+0f870e50a973fa820d4c409000059e181e8d242b`.

Harmless authentication tests (credentials used only in memory):

| Target | No key | Deliberately invalid Bearer | Tunnel environment's Bearer |
| --- | --- | --- | --- |
| Loopback `/api/v1/server/deploy-info` | 401 | 401 | 200; PID 1757595 |
| Microsoft HTTPS `/api/v1/server/deploy-info` | 401 | 401 | 200; PID 1757595 |
| Microsoft HTTPS `/mcp`, GET with `Accept: application/json` | 401 | 401 | 406, after authentication; request does not satisfy MCP GET protocol requirements |

The 401 body was `Unauthorized: invalid or missing API key header`. The MCP
406 is a protocol rejection, not a successful tool invocation; the controlled
A7Dev tool call above is the separate successful MCP-tool evidence.
An authenticated, read-only agents-list request for a deliberately unregistered
workspace returned **403 `Workspace outside public-client scope`**. That exact
policy check verifies the injected credential receives the public-client
workspace restrictions, rather than the internal-client bypass.
Unauthenticated Microsoft HTTPS `/health` returned 200, as explicitly exempted
by middleware. `/openapi.json` and documentation paths are also exempted in code.

## Limits and security implications

- **A leaked Microsoft tunnel URL alone did not permit protected operations**
  in these tests: both protected REST and `/mcp` rejected requests without a key.
  Public health/schema/docs remain reachable, and anonymous ingress still reaches
  the gateway's public attack surface and rate limiter.
- A valid gateway key authorizes the public-client scope; it is not per-person
  identity. Protect the environment-file copy as carefully as the gateway copy.
- “No authentication” is not evidence that OpenAI tunnel/account access controls
  are absent. This audit could not inspect remote organization membership,
  connector binding, tunnel permissions, or actual control-plane API-key scopes.
- The local injected header, credential acceptance, instance identity, and
  controlled tool/log correlation are verified. The precise cloud-side internal
  routing and UI metadata remain outside local visibility; they are not invented
  to make the diagram appear complete.
- This audit did not rotate keys, change auth, implement OAuth, restart services,
  or test destructive/mutating operations. Existing earlier tunnel error events
  were observed, but the controlled read-only invocation succeeded.

Installed implementation evidence: `src/agentporter/middleware.py` (header
selection, exemptions, principal), `auth.py` (constant-time comparison),
`config.py::_load_or_generate_api_key`, `client_policy.py::check`, and
`server.py` (tool wrappers, middleware wiring, deployment-info route), all under
the running release directory identified above. Local setup documentation
`docs/openai-tunnel-setup.md` independently describes the same `env:` header
injection; live unit/process evidence, rather than that document alone, supports
the findings.
