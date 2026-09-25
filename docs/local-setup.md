# Local Installation & Setup

AgentPorter currently targets Linux and WSL2.

## Requirements

- Python 3.11+
- Bubblewrap (`bwrap`)
- ripgrep (`rg`)
- `patch`
- Git
- R only if you want to execute R workloads

## Install

```bash
git clone https://github.com/lennon-li/AgentPorter.git
cd AgentPorter
pip install -e ".[dev]"
```

## Local configuration

AgentPorter keeps mutable configuration outside the package under
`~/.config/agentporter/`.

### Workspaces

Create `~/.config/agentporter/workspaces.yaml`:

```yaml
workspaces:
  my-project:
    path: /home/user/projects/my-project
    writable: true
    description: "Development workspace"
    allow_execute: true
    allow_git: true
    allow_artifacts: true
    allow_agent_dispatch: false
    local_http_ports: []
```

Enable worker delegation only for projects where host-user CLI execution is an
acceptable trust boundary. Add exact loopback ports only when an MCP client
must test a host-local service.

### Server/security

Create `~/.config/agentporter/config.yaml`:

```yaml
server:
  host: "127.0.0.1"
  port: 8765

security:
  auth: "api_key"
  header_name: "X-AgentPorter-Key"
  allowed_hosts:
    - "127.0.0.1"
    - "127.0.0.1:*"
    - "localhost"
    - "localhost:*"

sandbox:
  backend: "bubblewrap"
  network: false
  default_timeout_seconds: 30
  max_timeout_seconds: 900
  max_output_bytes: 102400
  max_job_log_bytes: 10485760
```

Remote hostnames and client-specific compatibility headers are opt-in local
configuration; they are intentionally not package defaults.

### API key

On first startup AgentPorter creates:

```text
~/.config/agentporter/secrets.env
```

with an `AGENTPORTER_API_KEY` and mode `0600`. To provide your own key:

```bash
printf 'AGENTPORTER_API_KEY=%s\n' 'your-high-entropy-key' \
  > ~/.config/agentporter/secrets.env
chmod 600 ~/.config/agentporter/secrets.env
```

## Diagnose

```bash
agentporter doctor
```

This reports runtime availability and configuration locations without printing
the API key.

## Run

```bash
agentporter serve --host 127.0.0.1 --port 8765
```

Keep localhost binding as the default. If a cloud MCP client needs access,
place a separately authenticated/controlled HTTPS tunnel or reverse proxy in
front of this local listener and explicitly allow that hostname.
