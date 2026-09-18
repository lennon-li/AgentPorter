# AgentPorter: Dogfooding Lessons Learned

This document captures the real-world operational lessons, failure modes, and architectural discoveries made while dogfooding **AgentPorter** with **Microsoft Copilot Studio**, **Microsoft 365 Copilot Desktop**, **Cloudflare Zero Trust Tunnels**, and corporate network environments.

---

## 1. Copilot Studio Action Path Traversal (`/` vs `/mcp`)

### Problem
When configuring a Model Context Protocol (MCP) action in Microsoft Copilot Studio with a server URL like `https://m3.biostats.ai`, Copilot Studio sends its JSON-RPC requests to the **root path** (`POST /`), rather than appending `/mcp`.

The official Python MCP SDK (`mcp.server.mcpserver.MCPServer.streamable_http_app()`) mounts exclusively on the path `/mcp`. As a result, incoming Copilot Studio requests immediately fail with:
> `404 Not Found: Path '/' does not exist`

### Solution
AgentPorter's `SecurityMiddleware` transparently rewrites incoming requests where `scope["path"] in ("/", "")` to `"/mcp"` (and updates `scope["raw_path"] = b"/mcp"`). This allows Copilot Studio to connect cleanly without requiring users to manually specify `/mcp` in the action endpoint configuration.

---

## 2. Microsoft 365 Desktop Channel User Connection Authorization

### Problem
Even when an MCP action connects successfully in the Copilot Studio **web test canvas**, the **Microsoft 365 Copilot Windows Desktop App** (and Teams) maintains a separate, per-user connection authorization state.

If this authorization is missing or stale, the desktop app fails with a generic error:
> *"Connector request failed Couldn't retrieve the requested items, 'Not Found'"*

### Solution
1. In Copilot Studio, navigate to **Channels** &rarr; **Microsoft 365 Copilot** &rarr; **User connections** (URL pattern: `https://copilotstudio.microsoft.com/.../channels/m365copilot/conversations/.../user-connections`).
2. Ensure the MCP action connection is explicitly toggled to **Connected** for the user's Entra ID account.
3. Click **Publish** in Copilot Studio.
4. In the Windows Copilot Desktop app, start a **New Chat** (to evict stale channel session cache).
5. **Critical Note**: Whenever an action's URL, authentication key, or parameters are modified, the user connection must be re-verified and the agent re-published.

---

## 3. Host Header Whitelisting on Custom Domains & Proxies

### Problem
AgentPorter's security layer validates the HTTP `Host` header against an authorized whitelist (`ALLOWED_HOSTS`) to prevent DNS rebinding attacks. When a custom domain (e.g. `m3.biostats.ai`) is routed through a reverse proxy or tunnel, the gateway rejects requests if the domain is not explicitly whitelisted:
> `403 Forbidden: Host header not allowed`

### Solution
AgentPorter's configuration now:
1. Expands default whitelist patterns to include popular tunneling platforms (`*.trycloudflare.com`, `*.devtunnels.ms`, `*.lhr.life`, `*.pinggy.link`, `*.pinggy.net`, `*.ts.net`).
2. Supports the `ALLOWED_HOSTS` environment variable (comma-separated, e.g. `ALLOWED_HOSTS=*.biostats.ai,m3.biostats.ai`) and configuration file overrides.
3. Automatically validates hostnames with or without explicit port specifications (`example.com:443` vs `example.com`).

---

## 4. Corporate Firewall Egress & Ingress Relay Architecture

### Problem
Enterprise and institutional networks (e.g. healthcare, government, university subnets) often enforce strict firewall policies:
- **Port 7844 (QUIC/UDP) Blocked**: Cloudflare tunnels default to QUIC over UDP port 7844, which corporate firewalls drop with `connection reset by peer`.
- **ACME / Let's Encrypt TLS Interception**: Outbound HTTPS requests to `acme-v02.api.letsencrypt.org` (used by Tailscale Funnel and Caddy) receive TCP RST during corporate network filtering hours.
- **Dynamic Subdomain Churn**: Free anonymous tunneling services (e.g. quick tunnels, free Pinggy) rotate subdomains on restart or expire after 60 minutes, breaking Copilot Studio actions.

### Solution: The Relay Mesh Topology
To achieve 100% reliable, permanent connectivity without requiring corporate firewall rule changes:
```text
Microsoft Copilot Studio (Cloud)
             │
             ▼  HTTPS
     Cloudflare Edge (m3.biostats.ai)
             │
             ▼  QUIC (Port 7844)
    Unrestricted Node (e.g. Home Mac Mini)
             │
             ▼  Private Tailscale Mesh VPN
    Internal Workstation (Asgard / WSL Port 8000)
```
- The external connector runs on an unrestricted node (home machine, VPS, or cloud VM) that connects to Cloudflare Edge.
- The external connector forwards requests across a private **Tailscale** network directly to the local development gateway on the office machine.
- Alternatively, **SSH reverse tunnels** over standard SSH port 22 (`localhost.run`) or HTTPS port 443 (`Pinggy`) can pass through corporate firewalls cleanly because SSH traffic is uninspected.

---

## 5. Cloudflare Named Tunnels with Custom Domains

### Problem
When creating a Cloudflare Named Tunnel and adding a `CNAME` in a third-party registrar (such as GoDaddy) pointing to `<uuid>.cfargotunnel.com`, external DNS queries resolve to an unroutable virtual IPv6 address (`fd10:aec2:5dae::`), and public clients receive:
> *"The remote name could not be resolved"*

### Solution
Cloudflare Tunnels only route public web traffic to a custom domain when:
1. The domain (e.g. `biostats.ai`) is added to Cloudflare as an active site with nameservers delegated to Cloudflare.
2. In Cloudflare DNS, the CNAME record for the tunnel subdomain (e.g. `m3`) has **Proxy status set to Proxied (Orange Cloud ☁️)**.
3. Once proxied, Cloudflare Edge intercepts public requests on Anycast IPs, terminates TLS with an automated universal SSL certificate, and routes the traffic down the tunnel.
