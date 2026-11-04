"""Local HTTP client tool for explicitly allowed loopback services."""

from typing import Optional
import httpx
from agentporter.workspaces.registry import WorkspaceRegistry


def create_local_http_tool(registry: WorkspaceRegistry):
    def local_http_request(
        workspace_id: str,
        port: int,
        method: str = "GET",
        path: str = "/",
        body: Optional[str] = None,
    ) -> dict:
        """Request a loopback service only when the workspace explicitly allows the port."""
        ws = registry.get(workspace_id)

        if not (1 <= port <= 65535):
            raise ValueError(f"Invalid port number: {port}")
        if port not in ws.local_http_ports:
            raise PermissionError(
                f"Loopback port {port} is not allowed for workspace '{workspace_id}'. "
                "Add it to local_http_ports in local configuration."
            )

        clean_path = "/" + path.lstrip("/")
        if len(clean_path) > 4096:
            raise ValueError("HTTP path is too long")
        if body is not None and len(body.encode("utf-8")) > 1024 * 1024:
            raise ValueError("HTTP request body exceeds 1 MiB")

        url = f"http://127.0.0.1:{port}{clean_path}"
        headers = {"User-Agent": "AgentPorter-LocalClient/0.1"}
        try:
            with httpx.Client(timeout=10.0, follow_redirects=False) as client:
                resp = client.request(
                    method=method.upper(),
                    url=url,
                    headers=headers,
                    content=body.encode("utf-8") if body else None,
                )
                text = resp.text
                return {
                    "status_code": resp.status_code,
                    "headers": {
                        k: v for k, v in resp.headers.items()
                        if k.lower() not in {"set-cookie", "authorization", "proxy-authorization"}
                    },
                    "body": text[:100000],
                    "truncated": len(text) > 100000,
                }
        except Exception as e:
            return {"error": f"Failed to connect to allowed loopback port {port}: {e}"}

    return local_http_request
