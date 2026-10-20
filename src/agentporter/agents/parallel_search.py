"""The one allowlisted anonymous web-search MCP server for delegated workers."""

from __future__ import annotations

import json
from pathlib import Path

PARALLEL_MCP_NAME = "parallel-search"
PARALLEL_MCP_URL = "https://search.parallel.ai/mcp"
PARALLEL_MCP_TOOLS = ("web_search", "web_fetch")


def codex_config_toml() -> str:
    """Return the additive TOML fragment for Codex's temporary profile."""
    return (
        f"mcp_servers.{PARALLEL_MCP_NAME} = {{ "
        f"url = {json.dumps(PARALLEL_MCP_URL)}, enabled = true, "
        f"enabled_tools = {json.dumps(list(PARALLEL_MCP_TOOLS))} }}\n"
    )


def copilot_config_path() -> str:
    """Return the packaged additive Copilot configuration, never a user profile."""
    return str(Path(__file__).with_name("parallel_search_copilot.json"))


def opencode_mcp_config() -> dict[str, object]:
    """Return OpenCode's remote-MCP block for merging into a run profile."""
    return {
        "mcp": {
            PARALLEL_MCP_NAME: {
                "type": "remote",
                "url": PARALLEL_MCP_URL,
                "enabled": True,
                "oauth": False,
            }
        },
        "tools": {
            f"{PARALLEL_MCP_NAME}_*": False,
            **{f"{PARALLEL_MCP_NAME}_{tool}": True for tool in PARALLEL_MCP_TOOLS},
        },
    }
