# Migration Guide (From Legacy Custom Gateway to AgentPorter)

This document outlines how to migrate an existing monolithic or custom MCP gateway setup to the standardized AgentPorter package.

---

## 1. Current State vs. Target State

### Legacy Setup (Monolithic)
- Code: Custom codebase in a standalone folder (e.g. `~/legacy-gateway/`)
- Configuration: Non-standard local configuration files
- Runtime State: Custom database and log paths
- MCP Port: Default port (e.g. `8000`)
- Active Client: Orchestrator connected via tunnel

### Target State (AgentPorter)
- Code: Installable Python package `agentporter`
- Configuration: Standard XDG location `~/.config/agentporter/` (`config.yaml`, `workspaces.yaml`, `secrets.env`)
- Runtime State: Standard XDG location `~/.local/state/agentporter/` (`jobs.db`, logs, synthetic `/etc`)
- MCP Port: Configurable (default `8765`)
- Active Client: Multiple MCP clients connected directly or via ingress tunnel

---

## 2. Step-by-Step Migration Plan

### Step 1: Install AgentPorter Package
Install the package in an isolated virtual environment or tool environment (e.g. via `pipx` or `uv tool`):
```bash
uv tool install --editable ~/repos/AgentPorter
```

### Step 2: Configure Workspaces and Credentials
Migrate existing workspaces and secrets to the standard XDG directories:
```bash
mkdir -p ~/.config/agentporter
mkdir -p ~/.local/state/agentporter

# Create workspace registry
cat << 'EOF' > ~/.config/agentporter/workspaces.yaml
workspaces:
  demo-project:
    path: /path/to/project
    writable: true
    description: "Main workspace"
EOF

# Set API key (reusing existing key if preserving active client configurations)
echo "AGENTPORTER_API_KEY=your-existing-or-new-key" > ~/.config/agentporter/secrets.env
chmod 0600 ~/.config/agentporter/secrets.env
```

### Step 3: Verify with Doctor
```bash
agentporter doctor
```

### Step 4: Launch AgentPorter on a Parallel Port
Launch AgentPorter on port 8765 to test side-by-side with the old gateway without interference:
```bash
agentporter serve --port 8765
```

### Step 5: Run Acceptance Test Suite
Execute the test suite against the running instance:
```bash
pytest -v tests/
```

### Step 6: Repoint Tunnel or Switch Action
Update the tunnel destination or launch a new tunnel pointing to port 8765:
```bash
cloudflared tunnel --url http://127.0.0.1:8765
```
Update the Server URL in the orchestrator action settings.

### Step 7: End-to-End Validation
Test common operations from the client:
1. `list_workspaces`
2. Sandboxed calculation: `cat(100/pi)`
3. Python calculation: `import math; print(100/math.pi)`
4. Git inspection: `git_status`
5. Agent inspection: `list_agents`

### Step 8: Rollback Plan
If any issues arise:
1. Stop AgentPorter on port 8765.
2. Restart the legacy gateway on port 8000.
3. Repoint the tunnel back to `http://127.0.0.1:8000`.
4. Orchestrator resumes immediate operation without reconfiguration.
