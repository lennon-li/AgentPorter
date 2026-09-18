# Connecting MCP Clients to AgentPorter

AgentPorter exposes MCP over Streamable HTTP.

## Local clients

Endpoint:

```text
http://127.0.0.1:8765/mcp
```

Authenticate with:

```text
X-AgentPorter-Key: <key>
```

The key is stored in `~/.config/agentporter/secrets.env`.

If a client only supports stdio, use a compatible stdio-to-HTTP MCP bridge.
AgentPorter does not require a specific bridge implementation.

## Remote/cloud clients

AgentPorter binds to localhost by default. A cloud MCP client therefore needs
an HTTPS ingress mechanism such as a named tunnel, reverse proxy, VPN gateway,
or another controlled relay.

When enabling remote ingress:

1. Keep AgentPorter itself on `127.0.0.1`.
2. Configure HTTPS/authentication at the ingress layer as appropriate.
3. Add the **specific** public hostname to AgentPorter's `allowed_hosts`.
4. Keep `X-AgentPorter-Key` configured in the MCP client.
5. Do not use broad wildcard tunnel domains unless you have a specific reason.

Example local configuration:

```yaml
security:
  allowed_hosts:
    - "127.0.0.1"
    - "localhost"
    - "my-agentporter.example.net"
```

Client-specific legacy header names can be configured locally with
`security.legacy_header_name`; they are not enabled by default.
