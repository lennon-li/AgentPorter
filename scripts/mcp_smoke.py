"""Generic AgentPorter MCP smoke test.

Usage:
  AGENTPORTER_API_KEY=... python scripts/mcp_smoke.py

Optional:
  AGENTPORTER_URL=http://127.0.0.1:8765/mcp
  AGENTPORTER_WORKSPACE=my-project
"""

import asyncio
import json
import os

import httpx
from mcp.client.session import ClientSession
from mcp.client.streamable_http import streamable_http_client

URL = os.environ.get("AGENTPORTER_URL", "http://127.0.0.1:8765/mcp")
KEY = os.environ.get("AGENTPORTER_API_KEY", "")
WORKSPACE = os.environ.get("AGENTPORTER_WORKSPACE", "")


async def main():
    if not KEY:
        raise SystemExit("Set AGENTPORTER_API_KEY in the environment")

    headers = {"X-AgentPorter-Key": KEY}
    async with httpx.AsyncClient(headers=headers, timeout=30.0) as client:
        async with streamable_http_client(URL, http_client=client) as (read_stream, write_stream):
            async with ClientSession(read_stream, write_stream) as session:
                await session.initialize()

                caps = await session.call_tool("get_capabilities", arguments={})
                print("get_capabilities:", caps.content[0].text)

                workspaces = await session.call_tool("list_workspaces", arguments={})
                print("list_workspaces:", [c.text for c in workspaces.content])

                if WORKSPACE:
                    info = await session.call_tool(
                        "workspace_info", arguments={"workspace_id": WORKSPACE}
                    )
                    print("workspace_info:", info.content[0].text)

    print("AgentPorter MCP smoke test: PASS")


if __name__ == "__main__":
    asyncio.run(main())
