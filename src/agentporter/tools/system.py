"""System and workspace MCP tools."""

import subprocess
from agentporter import __version__
from agentporter.workspaces.registry import WorkspaceRegistry
from agentporter.sandbox.base import SandboxBackend


def _bwrap_version() -> str:
    try:
        res = subprocess.run(
            ["bwrap", "--version"], capture_output=True, text=True, timeout=3
        )
        raw = (res.stdout + res.stderr).strip()
        return raw or "available"
    except Exception:
        return "unknown"


def create_system_tools(registry: WorkspaceRegistry, sandbox: SandboxBackend):
    def get_capabilities() -> dict:
        sandbox_available = sandbox.is_available()
        return {
            "gateway_version": __version__,
            "transport": "mcp_streamable_http",
            "auth": "header_api_key",
            "sandbox": {
                "backend": "bubblewrap",
                "available": sandbox_available,
                "version": _bwrap_version() if sandbox_available else "unavailable",
                "network": "disabled",
            },
            "supported_tools": [
                "get_capabilities", "list_workspaces", "workspace_info",
                "list_files", "search_text", "read_file", "write_file", "apply_patch", "mkdir", "move_path", "trash_path",
                "exec_run", "exec_start", "job_status", "job_output", "job_result", "job_cancel",
                "git_status", "git_diff", "git_log", "git_show",
                "local_http_request", "list_artifacts", "read_artifact",
                "list_agents", "dispatch_agent",
            ],
        }

    def list_workspaces() -> list[dict]:
        return registry.list_all()

    def workspace_info(workspace_id: str) -> dict:
        return registry.get_info(workspace_id)

    return get_capabilities, list_workspaces, workspace_info
