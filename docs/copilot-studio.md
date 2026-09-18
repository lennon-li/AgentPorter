# Microsoft Copilot Studio Integration

Copilot Studio can use AgentPorter as a remote MCP server. This is a
client-specific deployment pattern; Copilot Studio is not required by
AgentPorter.

## Architecture

```text
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
```

Because Copilot Studio cannot reach workstation localhost directly, configure a
controlled HTTPS ingress (for example, a named tunnel or reverse proxy). Add the
**exact** ingress hostname to `security.allowed_hosts`.

## MCP connection

In Copilot Studio, create an MCP connection with:

- Server URL: your HTTPS ingress URL with `/mcp` as required by the connector.
- Authentication: API key.
- Parameter location: Header.
- Header name: `X-AgentPorter-Key`.
- Value: the key from `~/.config/agentporter/secrets.env`.

After discovery, Copilot Studio should see AgentPorter's registered MCP tools.

## Suggested agent instructions

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

For a personal Copilot deployment, keep client-specific aliases, routing
preferences, legacy headers, and migration notes in a separate private
deployment repository rather than AgentPorter core.
