# AgentPorter: Dogfooding Lessons Learned

This document captures operational lessons, failure modes, and architectural discoveries made while dogfooding **AgentPorter** with orchestrators like **Microsoft Copilot Studio**, **Microsoft 365 Copilot Desktop**, **Cloudflare Zero Trust Tunnels**, and restricted corporate network environments.

---

## 1. Orchestrator Action Path Traversal (`/` vs `/mcp`)

### Problem
When configuring a Model Context Protocol (MCP) action in Microsoft Copilot Studio with a server URL like `https://agent.example.com`, the orchestrator sends its JSON-RPC requests to the **root path** (`POST /`), rather than appending `/mcp`.

The official Python MCP SDK (`mcp.server.mcpserver.MCPServer.streamable_http_app()`) mounts exclusively on `/mcp`. As a result, incoming requests fail immediately with:
> `404 Not Found: Path '/' does not exist`

### Solution
AgentPorter's `SecurityMiddleware` transparently rewrites incoming requests where `scope["path"] in ("/", "")` to `"/mcp"` (and updates `scope["raw_path"] = b"/mcp"`). This allows orchestrators to connect cleanly without requiring users to manually specify `/mcp` in endpoint action configurations.

---

## 2. Desktop Channel User Connection Authorization

### Problem
Even when an MCP action connects successfully in an orchestrator's web test canvas (e.g., Copilot Studio Web), desktop and mobile clients (such as the **Microsoft 365 Copilot Windows Desktop App**) may maintain a separate per-user connection authorization state.

If this authorization is missing or stale, the client fails with a generic error:
> *"Connector request failed Couldn't retrieve the requested items, 'Not Found'"*

### Solution
1. In the orchestrator settings, navigate to **Channels** &rarr; **Microsoft 365 Copilot** &rarr; **User connections**.
2. Ensure the MCP action connection is explicitly toggled to **Connected** for the user's account.
3. Click **Publish** in the orchestrator console.
4. In the desktop application, start a **New Chat** (to evict stale channel session cache).
5. **Critical Note**: Whenever an action's URL, authentication key, or parameters are modified, user connections must be re-verified and the agent re-published.

---

## 3. Host Header Whitelisting on Custom Domains & Proxies

### Problem
AgentPorter's security layer validates the HTTP `Host` header against an authorized whitelist (`ALLOWED_HOSTS`) to prevent DNS rebinding attacks. When a custom domain (e.g. `agent.example.com`) is routed through a reverse proxy or tunnel, the gateway rejects requests if the domain is not explicitly whitelisted:
> `403 Forbidden: Host header not allowed`

### Solution
AgentPorter's configuration:
1. Expands default whitelist patterns to include popular tunneling platforms (`*.trycloudflare.com`, `*.devtunnels.ms`, `*.lhr.life`, `*.pinggy.link`, `*.pinggy.net`, `*.ts.net`).
2. Supports the `ALLOWED_HOSTS` environment variable (comma-separated, e.g. `ALLOWED_HOSTS=*.example.com,agent.example.com`) and configuration file overrides.
3. Automatically validates hostnames with or without explicit port specifications (`example.com:443` vs `example.com`).

---

## 4. Corporate Firewall Egress & Ingress Relay Architecture

### Problem
Enterprise and institutional networks (e.g. corporate, healthcare, university subnets) often enforce strict firewall policies:
- **Port 7844 (QUIC/UDP) Blocked**: Cloudflare tunnels default to QUIC over UDP port 7844, which restricted corporate firewalls drop with `connection reset by peer`.
- **ACME / Let's Encrypt TLS Interception**: Outbound HTTPS requests to ACME certificate authorities (used by automatic TLS proxies) receive TCP resets during network filtering hours.
- **Dynamic Subdomain Churn**: Free anonymous tunneling services rotate subdomains on restart or expire after 60 minutes, breaking orchestrator action configurations.

### Solution: The Relay Mesh Topology
To achieve 100% reliable, permanent connectivity without requiring corporate firewall rule changes:
```text
Orchestrator Cloud (e.g. Copilot Studio)
             │
             ▼  HTTPS
     Cloudflare Edge (agent.example.com)
             │
             ▼  QUIC (Port 7844)
    Unrestricted Node (e.g. Cloud VM / Home Node)
             │
             ▼  Private Mesh VPN (e.g. Tailscale)
    Target Development Workstation (Port 8765)
```
- The external connector runs on an unrestricted node (cloud VM or external machine) that connects to Cloudflare Edge.
- The external connector forwards requests across a private **Tailscale** network directly to the local development gateway on the office workstation.
- Alternatively, **SSH reverse tunnels** over standard SSH port 22 (`localhost.run`) or HTTPS port 443 (`Pinggy`) can pass through corporate firewalls cleanly because SSH traffic is uninspected.

---

## 5. Cloudflare Named Tunnels with Custom Domains

### Problem
When creating a Cloudflare Named Tunnel and adding a `CNAME` in a third-party registrar pointing to `<uuid>.cfargotunnel.com`, external DNS queries resolve to an unroutable virtual IPv6 address (`fd10:aec2:5dae::`), and public clients receive:
> *"The remote name could not be resolved"*

### Solution
Cloudflare Tunnels only route public web traffic to a custom domain when:
1. The domain (e.g. `example.com`) is added to Cloudflare as an active site with nameservers delegated to Cloudflare.
2. In Cloudflare DNS, the CNAME record for the tunnel subdomain (e.g. `agent`) has **Proxy status set to Proxied (Orange Cloud ☁️)**.
3. Once proxied, Cloudflare Edge intercepts public requests on Anycast IPs, terminates TLS with an automated universal SSL certificate, and routes the traffic down the tunnel.
