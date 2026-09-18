"""System and workspace MCP tools."""

from agentporter.workspaces.registry import WorkspaceRegistry
from agentporter.sandbox.base import SandboxBackend


def create_system_tools(registry: WorkspaceRegistry, sandbox: SandboxBackend):
    def get_capabilities() -> dict:
        """Return gateway capabilities, sandbox status, and available runtimes."""
        return {
            "gateway_version": "0.1.0.dev0",
            "transport": "mcp_streamable_http",
            "auth": "header_api_key (X-AgentPorter-Key / X-M3-MCP-Key)",
            "sandbox": "bubblewrap_0.9.0" if sandbox.is_available() else "unavailable",
            "sandbox_network": "unshare-net (disabled)",
            "supported_tools": [
                "get_capabilities", "list_workspaces", "workspace_info",
                "list_files", "search_text", "read_file", "write_file", "apply_patch", "mkdir", "move_path", "trash_path",
                "exec_run", "exec_start", "job_status", "job_output", "job_result", "job_cancel",
                "git_status", "git_diff", "git_log", "git_show",
                "local_http_request", "list_artifacts", "read_artifact",
                "list_agents", "dispatch_agent"
            ]
        }

    def list_workspaces() -> list[dict]:
        """List all configured workspaces with ID, path, and writable status."""
        return registry.list_all()

    def workspace_info(workspace_id: str) -> dict:
        """Return comprehensive development context (git, language, runtimes) for a workspace."""
        return registry.get_info(workspace_id)

    return get_capabilities, list_workspaces, workspace_info
