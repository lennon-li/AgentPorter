# Local Dogfood Migration Guide (M3 Gateway to AgentPorter)

> **IMPORTANT**: This document outlines the planned future migration path. **DO NOT EXECUTE THIS MIGRATION YET.** The current working instance at `~/m3-agent-gateway` must remain active and untouched until AgentPorter has achieved proven parity.

---

## 1. Current State vs. Target State

### Current State
- Code: `~/m3-agent-gateway` (monolithic directory)
- Configuration: `~/.config/m3-agent-gateway/secrets.env`, `~/m3-agent-gateway/config/workspaces.yaml`
- Runtime State: `~/m3-agent-gateway/runtime/` (`jobs.db`, logs, synthetic `/etc`)
- MCP Port: `8000`
- Active Client: Microsoft Copilot Studio (M3) via Cloudflare Tunnel (`trend-sun-bride-worm.trycloudflare.com`)

### Target Future State
- Code: Installable Python package `agentporter` (from `lennon-li/AgentPorter`)
- Configuration: Standard XDG location `~/.config/agentporter/` (`config.yaml`, `workspaces.yaml`, `secrets.env`)
- Runtime State: Standard XDG location `~/.local/state/agentporter/` (`jobs.db`, logs, synthetic `/etc`)
- MCP Port: Configurable (default `8765`)
- Active Client: Microsoft Copilot Studio (M3) + other MCP clients directly or via tunnel

---

## 2. Step-by-Step Migration Plan (For Future Execution)

### Step 1: Install AgentPorter Package
Install the package in an isolated virtual environment or tool environment (e.g. via `pipx` or `uv tool`):
```bash
uv tool install --editable /home/yeli/repos/AgentPorter
```

### Step 2: Translate Configuration
Migrate existing workspaces and secrets to the standard XDG directories:
```bash
mkdir -p ~/.config/agentporter
mkdir -p ~/.local/state/agentporter

# Copy workspace registry
cp ~/m3-agent-gateway/config/workspaces.yaml ~/.config/agentporter/workspaces.yaml

# Copy existing secret key to avoid breaking Copilot Studio authorization
KEY=$(grep -E '^M3_MCP_KEY=' ~/.config/m3-agent-gateway/secrets.env | cut -d'=' -f2-)
echo "AGENTPORTER_API_KEY=$KEY" > ~/.config/agentporter/secrets.env
echo "M3_MCP_KEY=$KEY" >> ~/.config/agentporter/secrets.env
chmod 0600 ~/.config/agentporter/secrets.env
```

### Step 3: Verify with Doctor
```bash
agentporter doctor
```

### Step 4: Launch AgentPorter on Parallel Port
Launch AgentPorter on port 8765 to test side-by-side with the old gateway without interference:
```bash
agentporter serve --port 8765
```

### Step 5: Run Acceptance Test Suite
Execute the full integration test suite against the running instance:
```bash
pytest -v tests/integration/
```

### Step 6: Repoint Cloudflare Tunnel or Switch Copilot Action
Update the tunnel destination or launch a new tunnel pointing to port 8765:
```bash
cloudflared tunnel --url http://127.0.0.1:8765
```
Update the Server URL in Copilot Studio Action settings.

### Step 7: End-to-End Validation from Copilot Studio
Ask Copilot Studio to execute:
1. `list_workspaces`
2. Sandboxed R calculation `cat(100/pi)`
3. Sandboxed Python calculation `import math; print(100/math.pi)`
4. Git status check on `m3-poc`
5. `list_agents` and an independent read-only code review dispatch

### Step 8: Rollback Plan
If any regressions occur:
1. Stop AgentPorter on port 8765.
2. Restart `~/m3-agent-gateway` on port 8000 via `scripts/start.sh`.
3. Repoint tunnel to `http://127.0.0.1:8000`.
4. Copilot Studio resumes immediate operation without reconfiguration.

### Step 9: Decommission Legacy Gateway
Only after several days of completely successful dogfooding with M3 and other clients:
1. Archive `~/m3-agent-gateway`.
2. Update scripts and documentation.
