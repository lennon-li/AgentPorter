# Microsoft Copilot Studio Integration

Copilot Studio can use AgentPorter as a remote MCP server. This is a
client-specific deployment pattern; Copilot Studio is not required by
AgentPorter.

## Architecture

```text
<<<<<<< HEAD
Copilot Studio (cloud)
       |
       | HTTPS MCP
       v
controlled HTTPS ingress
       |
       v
AgentPorter on 127.0.0.1:8765
       |
       +--> Bubblewrap direct execution
       +--> workspace tools
       +--> explicitly enabled worker CLI delegation
=======
Microsoft Copilot Studio (Cloud)
             │
             │ HTTPS (Streamable HTTP / SSE)
             ▼
   Microsoft Dev Tunnels (Azure Relay Ingress)
             │
             │ HTTP (localhost)
             ▼
   AgentPorter Gateway (WSL2 / Linux localhost:8765)
             │
   ┌─────────┴─────────┐
   ▼                   ▼
Bubblewrap Sandbox   CLI Agent Workers
(R, Python, Bash)    (Codex, Claude, etc.)
>>>>>>> origin/main
```

Because Copilot Studio cannot reach workstation localhost directly, configure a
controlled HTTPS ingress (for example, a named tunnel or reverse proxy). Add the
**exact** ingress hostname to `security.allowed_hosts`.

<<<<<<< HEAD
## MCP connection

In Copilot Studio, create an MCP connection with:

- Server URL: your HTTPS ingress URL with `/mcp` as required by the connector.
- Authentication: API key.
- Parameter location: Header.
- Header name: `X-AgentPorter-Key`.
- Value: the key from `~/.config/agentporter/secrets.env`.

After discovery, Copilot Studio should see AgentPorter's registered MCP tools.

## Suggested agent instructions
=======
## 2. Ingress & Tunnel Setup (Microsoft Dev Tunnels)

Because Copilot Studio runs in Microsoft cloud infrastructure, it cannot connect directly to `localhost`. We use **Microsoft Dev Tunnels** (`devtunnel` CLI). This routes traffic natively through Microsoft Azure relays (`*.devtunnels.ms`), ensuring data stays entirely within the Microsoft/GitHub enterprise trust boundary (no third-party commercial CDNs like Cloudflare).

### Step A: Authenticate to Dev Tunnels
Choose one of three supported identity options based on your environment:

1. **Option 1: GitHub Personal (`devtunnel user login -d -g`)**
   - Ideal for individual developers; zero enterprise approval required.
   - Run: `devtunnel user login -d -g` and enter the 8-character code at `https://github.com/login/device`.
2. **Option 2: GitHub Enterprise (`devtunnel user login -d -g`)**
   - Ideal for corporate environments with institutional compliance requirements.
   - Covered under Microsoft/GitHub Enterprise Data Protection Agreements (DPA).
   - Sign in with your GitHub Enterprise work account and authorize the device code.
3. **Option 3: Microsoft Entra ID / Azure (`devtunnel user login -d -e`)**
   - Direct sign-in using your corporate Microsoft 365 / Azure work account.
   - *Note: If your IT organization enforces Conditional Access policy restrictions on the Dev Tunnels app (Error 53003), use Option 1 or 2 instead.*

### Step B: Create a Persistent Tunnel (One-Time Setup)
Create a reusable, named tunnel that permits anonymous connection at the tunnel boundary (AgentPorter validates the API key on arrival):

```bash
# 1. Create a named tunnel with anonymous connect allowed
devtunnel create agentporter-tunnel --allow-anonymous

# 2. Map the AgentPorter gateway port (8765)
devtunnel port create agentporter-tunnel -p 8765
```

### Step C: Host the Tunnel & Start AgentPorter

```bash
# 1. Start AgentPorter
agentporter serve --port 8765

# 2. In another terminal, host the Dev Tunnel:
devtunnel host agentporter-tunnel
```

The CLI outputs your permanent HTTPS URL:
```text
Hosting port: 8765 -> https://<tunnel-id>-8765.use.devtunnels.ms
```
Unlike temporary tunnels, this subdomain is **persistent across restarts**.

---

## 3. Configuring Copilot Studio

1. Open **Microsoft Copilot Studio** and navigate to your Copilot agent.
2. Under **Actions**, click **Add an action** (or edit your existing action) and choose **Model Context Protocol (MCP)**.
3. Configure the MCP connection:
   - **Server URL**: `https://<tunnel-id>-8765.use.devtunnels.ms` (or `https://<tunnel-id>-8000.use.devtunnels.ms` for M3 port 8000)
   - **Authentication Type**: `API Key`
   - **Parameter Location**: `Header`
   - **Header Name**: `X-AgentPorter-Key` (or legacy `X-M3-MCP-Key`)
   - **API Key**: Retrieve from `~/.config/agentporter/secrets.env`.
4. Copilot Studio will connect and discover all registered tools:
   - System/Workspace: `get_capabilities`, `list_workspaces`, `workspace_info`
   - Files: `list_files`, `search_text`, `read_file`, `write_file`, `apply_patch`, `mkdir`, `move_path`, `trash_path`
   - Execution: `exec_run`, `exec_start`, `job_status`, `job_output`, `job_result`, `job_cancel`, `local_http_request`
   - Git: `git_status`, `git_diff`, `git_log`, `git_show`
   - Artifacts: `list_artifacts`, `read_artifact`
   - Agents: `list_agents`, `dispatch_agent`

---

## 4. Recommended System Prompt for Copilot Studio

In the Copilot agent's **Instructions** editor, configure guidance on workspace discipline:
>>>>>>> origin/main

```text
You are connected to a local development environment through AgentPorter.

Use MCP tools to inspect code and execute tests instead of claiming actions
without evidence. Work only in registered workspaces and use relative paths.

Direct execution is sandboxed and has no network access. Worker-agent
delegation is a separate host-user trust boundary; check list_agents and
workspace permissions before dispatching.

Do not reveal credentials. Do not claim that an actual model was used unless
AgentPorter reports trusted runtime provenance; "unknown" is a valid answer.
```

<<<<<<< HEAD
For a personal Copilot deployment, keep client-specific aliases, routing
preferences, legacy headers, and migration notes in a separate private
deployment repository rather than AgentPorter core.
=======
---

## 5. Authorize User Connection for Microsoft 365 Copilot Desktop

Even if the agent connects successfully in the Copilot Studio web test canvas, the **Microsoft 365 Copilot desktop app** (and Teams) maintains a separate per-user authorization state. If this authorization is missing, the desktop app will report:
> *"Connector request failed Couldn't retrieve the requested items, 'Not Found'"*

To authorize:
1. In Copilot Studio, go to **Channels** -> **Microsoft 365 Copilot**.
2. Navigate to **User connections** (or open the channel connection settings):
   `https://copilotstudio.microsoft.com/c2/tenants/<tenant-id>/environments/<env-id>/bots/<bot-id>/channels/m365copilot/conversations/<conversation-id>/user-connections`
3. Verify that the MCP tool connection is explicitly set to **Connected** for your user account.
4. Click **Publish** to deploy the latest agent configuration to the Microsoft 365 Copilot channel.

---

## 6. Pre-flight Verification Checklist

- [ ] AgentPorter gateway is running (`agentporter serve` or systemd service active).
- [ ] Ingress tunnel is active and reachable (`curl -I <tunnel-url>/health` returns `200 OK`).
- [ ] Action configured in Copilot Studio with correct URL and `X-AgentPorter-Key` (or `X-M3-MCP-Key`) header.
- [ ] Copilot agent system instructions saved.
- [ ] Agent published to Microsoft 365 Copilot channel.
- [ ] User connection verified as **Connected** under M365 Copilot channel user connections.
- [ ] In the Windows Copilot Desktop app: Started a **New Chat** inside the custom agent from the right-hand sidebar.

>>>>>>> origin/main
