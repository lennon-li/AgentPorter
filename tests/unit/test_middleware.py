"""Unit tests for ASGI SecurityMiddleware."""

import pytest
from starlette.applications import Starlette
from starlette.responses import JSONResponse
from starlette.routing import Route
from starlette.testclient import TestClient
from agentporter.middleware import SecurityMiddleware
from agentporter.auth import RateLimiter


async def homepage(request):
    return JSONResponse({"status": "ok"})


def create_test_app(api_key="valid-key-123", max_payload=1024, rate_max=5):
    inner_app = Starlette(routes=[
        Route("/", homepage, methods=["GET", "POST"]),
        Route("/mcp", homepage, methods=["GET", "POST"]),
    ])
    limiter = RateLimiter(max_requests=rate_max, window_seconds=10.0)
    return SecurityMiddleware(
        app=inner_app,
        api_key=api_key,
        allowed_hosts=["127.0.0.1", "localhost", "testserver"],
        header_name="X-AgentPorter-Key",
        legacy_header_name="X-M3-MCP-Key",
        rate_limiter=limiter,
        max_payload_bytes=max_payload,
    )


def test_middleware_valid_auth():
    app = create_test_app()
    client = TestClient(app, base_url="http://testserver")

    # Primary header
    resp = client.get("/", headers={"X-AgentPorter-Key": "valid-key-123"})
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}

    # Legacy header
    resp = client.get("/", headers={"X-M3-MCP-Key": "valid-key-123"})
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}


def test_middleware_missing_or_invalid_auth():
    app = create_test_app()
    client = TestClient(app, base_url="http://testserver")

    # Missing
    resp = client.get("/")
    assert resp.status_code == 401

    # Invalid
    resp = client.get("/", headers={"X-AgentPorter-Key": "wrong-key"})
    assert resp.status_code == 401


def test_middleware_host_validation():
    app = create_test_app()
    # Malicious host
    client = TestClient(app, base_url="http://malicious.attacker.com")
    resp = client.get("/", headers={"X-AgentPorter-Key": "valid-key-123"})
    assert resp.status_code == 403


def test_middleware_payload_ceiling():
    app = create_test_app(max_payload=50)
    client = TestClient(app, base_url="http://testserver")
    large_body = "x" * 200
    resp = client.post(
        "/",
        content=large_body,
        headers={"X-AgentPorter-Key": "valid-key-123", "Content-Length": str(len(large_body))}
    )
    assert resp.status_code == 413


def test_middleware_rate_limiting():
    app = create_test_app(rate_max=3)
    client = TestClient(app, base_url="http://testserver")
    headers = {"X-AgentPorter-Key": "valid-key-123"}

    for _ in range(3):
        resp = client.get("/", headers=headers)
        assert resp.status_code == 200

    # 4th request exceeds rate limit
    resp = client.get("/", headers=headers)
    assert resp.status_code == 429


def test_middleware_health_endpoint():
    app = create_test_app()
    client = TestClient(app, base_url="http://testserver")
    # Health endpoint succeeds without API key (for public uptime/tunnel probes)
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json()["status"] == "healthy"
    assert resp.json()["service"] == "agentporter"

    # Health endpoint still enforces host header validation
    client_bad_host = TestClient(app, base_url="http://attacker.com")
    resp_bad = client_bad_host.get("/health")
    assert resp_bad.status_code == 403


def test_middleware_root_path_rewrite():
    # Verify that requests to '/' are rewritten to '/mcp'
    async def mcp_endpoint(request):
        return JSONResponse({"path": request.scope["path"]})

    inner_app = Starlette(routes=[Route("/mcp", mcp_endpoint, methods=["POST"])])
    limiter = RateLimiter(max_requests=10, window_seconds=10.0)
    app = SecurityMiddleware(
        app=inner_app,
        api_key="valid-key-123",
        allowed_hosts=["testserver"],
        rate_limiter=limiter,
    )
    client = TestClient(app, base_url="http://testserver")
    resp = client.post("/", headers={"X-AgentPorter-Key": "valid-key-123"})
    assert resp.status_code == 200
    assert resp.json() == {"path": "/mcp"}

