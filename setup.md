# AgentPorter setup

Start with [local setup](docs/local-setup.md) to install AgentPorter and define
workspace permissions. Use the generic [server configuration](examples/config.example.yaml)
and [workspace registry](examples/workspaces.example.yaml) as templates; keep
credentials and actual workspace paths in private local configuration.

For service installation and immutable releases, follow the
[deployment guide](docs/deployment.md). The [main service](examples/agentporter.service)
and [dedicated client service](examples/agentporter-chatgpt.service) are generic
examples that require local configuration.

To connect ChatGPT, follow the [secure MCP tunnel guide](docs/openai-tunnel-setup.md).
Configure a separate API key, configuration/state directories and loopback port
when running a dedicated instance. Verify its health, package fingerprint and
service PID before enabling client access.

Review the [security model](docs/security-model.md), [delegation guide](docs/delegation-guide.md)
and [action policy](docs/agent-roster-action-policy.md) before granting execution
or writable delegation. Tool discovery reports installed capabilities; it does
not grant workspace or provider access.
