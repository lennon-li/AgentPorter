# Connecting MCP Clients to AgentPorter

AgentPorter implements the standard Model Context Protocol (MCP) using Streamable HTTP. It can be consumed by any MCP-compliant client.

---

## 1. Authentication Overview

AgentPorter requires an API key passed in an HTTP header:
- Primary header: `X-AgentPorter-Key: <key>`
- Legacy header: `X-M3-MCP-Key: <key>`

The active key can be retrieved from:
```bash
cat ~/.config/agentporter/secrets.env
```

---

## 2. Connecting Claude Desktop / MCP Clients with Stdio-to-HTTP Bridge

For MCP clients that only support stdio transports (such as standard Claude Desktop installations), use an MCP proxy bridge (e.g. `mcp-proxy` or `curl-sse` bridge):

```json
{
  "mcpServers": {
    "agentporter": {
      "command": "npx",
      "args": [
        "-y",
        "mcp-remote-proxy",
        "--url",
        "http://127.0.0.1:8765/mcp",
        "--header",
        "X-AgentPorter-Key: <YOUR_KEY>"
      ]
    }
  }
}
```

---

## 3. Remote Ingress via Microsoft Dev Tunnels (Azure Relay)

When connecting an external cloud orchestrator (e.g., Microsoft Copilot Studio, ChatGPT Actions) to a local AgentPorter instance running inside WSL2:

1. Log in via your preferred identity provider:
   - **GitHub Personal**: `devtunnel user login -d -g`
   - **GitHub Enterprise**: `devtunnel user login -d -g` (with your enterprise work account)
   - **Microsoft Entra ID / Azure**: `devtunnel user login -d -e`
2. Create and host a persistent tunnel:
   ```bash
   devtunnel create agentporter-tunnel --allow-anonymous
   devtunnel port create agentporter-tunnel -p 8765
   devtunnel host agentporter-tunnel
   ```
3. Use the resulting permanent HTTPS URL (`https://<tunnel-id>-8765.use.devtunnels.ms`) as the MCP server endpoint in your remote client with the `X-AgentPorter-Key` header.

