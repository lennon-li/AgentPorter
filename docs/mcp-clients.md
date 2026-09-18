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

## 3. Remote Ingress via Cloudflare Quick Tunnel

When connecting an external cloud orchestrator (e.g., Microsoft Copilot Studio) to a local AgentPorter instance running inside WSL2:

1. Launch a Cloudflare tunnel pointing to your local port:
   ```bash
   cloudflared tunnel --url http://127.0.0.1:8765
   ```
2. Note the generated HTTPS domain:
   ```text
   https://example-subdomain.trycloudflare.com
   ```
3. Use this URL as the MCP server endpoint in your remote client with the `X-AgentPorter-Key` header.
