# Local Installation & Setup Guide

This guide describes how to install and configure AgentPorter on a host machine (Linux or WSL2).

---

## 1. System Requirements

- **Operating System**: Linux (Ubuntu 22.04+ recommended) or WSL2.
- **Python**: 3.11 or higher.
- **Bubblewrap**: Required for sandboxing (`sudo apt install bubblewrap`).
- **Ripgrep**: Required for fast text search (`sudo apt install ripgrep`).
- **Patch**: Required for unified diff patches (`sudo apt install patch`).
- **Git**: Required for git inspection tools.

---

## 2. Package Installation

```bash
# Clone the repository
git clone https://github.com/lennon-li/AgentPorter.git
cd AgentPorter

# Install package in your Python environment
pip install -e .
```

---

## 3. Configuration Setup

AgentPorter stores local configuration in `~/.config/agentporter/`:

```bash
mkdir -p ~/.config/agentporter
```

### A. Register Workspaces (`~/.config/agentporter/workspaces.yaml`)

```yaml
workspaces:
  my-project:
    path: /home/user/projects/my-project
    writable: true
    description: "Main development workspace"

  reference-repo:
    path: /home/user/projects/reference
    writable: false
    description: "Read-only reference codebase"
```

### B. Configure Server Options (`~/.config/agentporter/config.yaml`)

```yaml
server:
  host: "127.0.0.1"
  port: 8765

security:
  header_name: "X-AgentPorter-Key"
  legacy_header_name: "X-M3-MCP-Key"
  allowed_hosts:
    - "127.0.0.1"
    - "localhost"
    - "*.trycloudflare.com"
```

### C. API Key Setup (`~/.config/agentporter/secrets.env`)

If this file does not exist, AgentPorter generates a secure 32-byte key automatically on first launch and secures the file with permissions `0600`.

To set your own key manually:
```bash
echo "AGENTPORTER_API_KEY=your-secure-random-key" > ~/.config/agentporter/secrets.env
chmod 0600 ~/.config/agentporter/secrets.env
```

---

## 4. Running the Doctor Check

Verify your installation:

```bash
agentporter doctor
```

Example output:
```text
AgentPorter Doctor Diagnostic:
  Version: 0.1.0.dev0
  Python: 3.12.3
  Bubblewrap Sandbox: Available (/usr/bin/bwrap)
  Config Directory: /home/user/.config/agentporter
  State Directory: /home/user/.local/state/agentporter
  Registered Workspaces: 2
  Detected Worker Agents:
    • codex: Available (v0.154.0)
    • claude: Available (v2.1.274)
    • opencode: Available (v1.18.31)
    • agy: Available (v1.2.5)
```

---

## 5. Starting the Server

```bash
agentporter serve --host 127.0.0.1 --port 8765
```
