# Microsoft Copilot Studio Integration Guide

This guide details how to integrate Microsoft Copilot Studio (M3) with a local development environment via AgentPorter.

---

## 1. Architecture Flow

```text
Microsoft Copilot Studio (Cloud)
             │
             │ HTTPS (Streamable HTTP / SSE)
             ▼
   Cloudflare Quick Tunnel (Public HTTPS Ingress)
             │
             │ HTTP (localhost)
             ▼
   AgentPorter Gateway (WSL2 / Linux localhost:8765)
             │
   ┌─────────┴─────────┐
   ▼                   ▼
Bubblewrap Sandbox   CLI Agent Workers
(R, Python, Bash)    (Codex, Claude, etc.)
```

---

## 2. Ingress & Tunnel Setup

Because Copilot Studio runs in Microsoft cloud infrastructure, it cannot connect directly to `localhost`. A secure tunnel is required:

```bash
# 1. Start AgentPorter locally
agentporter serve --port 8765

# 2. Expose the port via Cloudflare Quick Tunnel
cloudflared tunnel --url http://127.0.0.1:8765
```

The tunnel provides a public HTTPS endpoint such as `https://random-words.trycloudflare.com`.

---

## 3. Configuring Copilot Studio

1. Open **Microsoft Copilot Studio** and navigate to your Copilot agent.
2. Under **Actions**, click **Add an action** and choose **Model Context Protocol (MCP)**.
3. Configure the MCP connection:
   - **Server URL**: `https://<your-subdomain>.trycloudflare.com`
   - **Authentication Type**: `API Key`
   - **Parameter Location**: `Header`
   - **Header Name**: `X-AgentPorter-Key` (or legacy `X-M3-MCP-Key`)
   - **API Key**: Retrieve from `~/.config/agentporter/secrets.env`.
4. Copilot Studio will connect and discover all registered tools:
   - System/Workspace: `get_capabilities`, `list_workspaces`, `workspace_info`
   - Files: `list_files`, `search_text`, `read_file`, `write_file`, `apply_patch`, `mkdir`, `move_path`, `trash_path`
   - Execution: `exec_run`, `exec_start`, `job_status`, `job_output`, `job_result`, `job_cancel`, `local_http_request`
   - Git: `git_status`, `git_diff`, `git_log`, `git_show`
   - Artifacts: `list_artifacts`, `read_artifact`
   - Agents: `list_agents`, `dispatch_agent`

---

## 4. Recommended System Prompt for Copilot Studio

In the Copilot agent's **Instructions** editor, configure guidance on workspace discipline:

```text
You are connected to a local developer workstation via AgentPorter.
Operating principles:
1. Grounding: When asked to inspect code, run tests, or modify files, use the available MCP tools instead of guessing.
2. Workspace Scope: Begin tasks by listing workspaces or querying workspace_info. Always use relative paths within the designated workspace.
3. Sandboxed Execution: You can execute commands (Python, R, bash) safely using exec_run or exec_start. Execution has no internet access.
4. Worker Delegation: For deep reasoning or specialist reviews, use list_agents to check available coding agents, then dispatch_agent and monitor with job_result.
5. Safety: Never reveal API keys or secret files. Do not perform destructive git operations.
```
