"""Local HTTP client tool for testing loopback services."""

from typing import Optional
import httpx
from agentporter.workspaces.registry import WorkspaceRegistry


def create_local_http_tool(registry: WorkspaceRegistry):
    def local_http_request(
        workspace_id: str,
        port: int,
        method: str = "GET",
        path: str = "/",
        body: Optional[str] = None
    ) -> dict:
        """Send an HTTP request strictly to a local application running on loopback (127.0.0.1)."""
        registry.get(workspace_id)

        if not (1 <= port <= 65535):
            raise ValueError(f"Invalid port number: {port}")

        clean_path = "/" + path.lstrip("/")
        url = f"http://127.0.0.1:{port}{clean_path}"

        headers = {"User-Agent": "AgentPorter-LocalClient/0.1"}
        try:
            with httpx.Client(timeout=10.0) as client:
                resp = client.request(
                    method=method.upper(),
                    url=url,
                    headers=headers,
                    content=body.encode("utf-8") if body else None
                )
                return {
                    "status_code": resp.status_code,
                    "headers": dict(resp.headers),
                    "body": resp.text[:100000],
                    "truncated": len(resp.text) > 100000
                }
        except Exception as e:
            return {
                "error": f"Failed to connect to local service on 127.0.0.1:{port}: {e}"
            }

    return local_http_request
