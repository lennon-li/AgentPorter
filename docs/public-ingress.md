# Public ingress ownership

AgentPorter is the reusable local package. It listens on its configured local
host and port, normally `127.0.0.1:8765`. It must not contain a
machine-specific tunnel hostname.

Public ingress belongs to the local deployment orchestrator. In the Asgard
setup, that orchestrator is m3. The m3 tunnel service owns the named tunnel,
discovers the active URL for each hosted port, and publishes those URLs under
its runtime directory.

Client configuration must consume the m3 runtime URL for the intended port.
Do not copy a generated `*.devtunnels.ms` address into AgentPorter source or a
general package document. Restarting AgentPorter should never require changing
a public client URL.

For a deployment that must publish an OpenAPI `servers` entry (for example,
ChatGPT Actions), set `AGENTPORTER_PUBLIC_URL` in that deployment's service
environment. AgentPorter then emits the configured URL without embedding a
tunnel hostname in the reusable package.

If an immutable public address is required, use a stable domain or reverse
proxy in front of the local listener.
