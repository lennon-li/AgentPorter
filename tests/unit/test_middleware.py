"""Unit tests for ASGI SecurityMiddleware."""

import asyncio

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
    inner_app = Starlette(routes=[Route("/", homepage, methods=["GET", "POST"])])
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


def test_oauth_metadata_probe_is_public_without_opening_mcp(tmp_path, monkeypatch):
    """Anonymous discovery gets 404; MCP calls and unsafe methods remain keyed."""
    from agentporter.config import Config
    from agentporter.server import create_asgi_app

    monkeypatch.setenv("AGENTPORTER_API_KEY", "test-only-not-production")
    cfg = Config(config_dir=tmp_path / "cfg", state_dir=tmp_path / "state")
    cfg.security.allowed_hosts.append("testserver")

    with TestClient(create_asgi_app(cfg), base_url="http://testserver") as client:
        for path in (
            "/.well-known/oauth-protected-resource/mcp",
            "/.well-known/oauth-protected-resource",
        ):
            assert client.get(path).status_code == 404
            assert client.head(path).status_code == 404
            assert client.post(path).status_code == 401
            assert client.get(path, headers={"Host": "untrusted.example"}).status_code == 403

        assert client.get("/mcp").status_code == 401


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


def test_middleware_streamed_payload_ceiling():
    app = create_test_app(max_payload=50)
    client = TestClient(app, base_url="http://testserver")

    def chunks():
        yield b"x" * 30
        yield b"y" * 30

    resp = client.post(
        "/",
        content=chunks(),
        headers={"X-AgentPorter-Key": "valid-key-123"},
    )
    assert resp.status_code == 413


def test_streaming_request_body_is_not_buffered():
    """An open MCP POST must reach the downstream app before EOF."""
    async def scenario():
        received = asyncio.Event()

        async def downstream(scope, receive, send):
            message = await receive()
            assert message["body"] == b"initialize"
            received.set()

        app = SecurityMiddleware(
            app=downstream,
            api_key="valid-key-123",
            allowed_hosts=["testserver"],
            rate_limiter=RateLimiter(max_requests=5, window_seconds=10.0),
            max_payload_bytes=1024,
        )

        messages = iter(
            [
                {"type": "http.request", "body": b"initialize", "more_body": True},
            ]
        )

        async def receive():
            try:
                return next(messages)
            except StopIteration:
                await asyncio.sleep(60)

        sent = []

        async def send(message):
            sent.append(message)

        scope = {
            "type": "http",
            "method": "POST",
            "path": "/mcp",
            "headers": [
                (b"host", b"testserver"),
                (b"x-agentporter-key", b"valid-key-123"),
            ],
            "client": ("127.0.0.1", 12345),
        }

        await asyncio.wait_for(app(scope, receive, send), timeout=1)
        assert received.is_set()

    asyncio.run(scenario())



def test_real_mcp_streaming_endpoint_rejects_undeclared_oversized_body(tmp_path, monkeypatch):
    """Exercise FastAPI + mounted MCP's own 413 path, not a bare ASGI handler."""
    from agentporter.config import Config
    from agentporter.server import create_asgi_app

    monkeypatch.setenv("AGENTPORTER_API_KEY", "test-only-not-production")
    cfg = Config(config_dir=tmp_path / "cfg", state_dir=tmp_path / "state")
    cfg.security.max_payload_bytes = 50
    cfg.security.allowed_hosts.append("testserver")

    def chunks():
        yield b"x" * 30
        yield b"y" * 30

    with TestClient(create_asgi_app(cfg), base_url="http://testserver") as client:
        result = client.post(
            "/mcp",
            content=chunks(),
            headers={
                "X-AgentPorter-Key": cfg.api_key,
                "Content-Type": "application/json",
                "Accept": "application/json, text/event-stream",
            },
        )
    assert result.status_code == 413, result.text
    assert "Request body too large" in result.text


def test_real_mcp_streaming_endpoint_checks_actual_bytes_even_with_lied_length(tmp_path, monkeypatch):
    from agentporter.config import Config
    from agentporter.server import create_asgi_app

    monkeypatch.setenv("AGENTPORTER_API_KEY", "test-only-not-production")
    cfg = Config(config_dir=tmp_path / "cfg", state_dir=tmp_path / "state")
    cfg.security.max_payload_bytes = 50
    cfg.security.allowed_hosts.append("testserver")

    with TestClient(create_asgi_app(cfg), base_url="http://testserver") as client:
        result = client.post(
            "/mcp",
            content=b"x" * 90,
            headers={
                "X-AgentPorter-Key": cfg.api_key,
                "Content-Length": "10",
                "Content-Type": "application/json",
                "Accept": "application/json, text/event-stream",
            },
        )
    assert result.status_code == 413, result.text


def test_mcp_sdk_default_four_mib_ceiling_not_raised_by_gateway(tmp_path, monkeypatch):
    from mcp.server.mcpserver import MCPServer
    from mcp.server.transport_security import DEFAULT_MAX_REQUEST_BODY_SIZE
    from agentporter.config import Config
    from agentporter.server import create_asgi_app

    monkeypatch.setenv("AGENTPORTER_API_KEY", "test-only-not-production")
    cfg = Config(config_dir=tmp_path / "cfg", state_dir=tmp_path / "state")
    cfg.security.max_payload_bytes = 10 * 1024 * 1024
    observed = []
    original = MCPServer.streamable_http_app

    def spy(self, **kwargs):
        observed.append(kwargs.get("max_request_body_size"))
        return original(self, **kwargs)

    monkeypatch.setattr(MCPServer, "streamable_http_app", spy)
    create_asgi_app(cfg)
    assert observed == [DEFAULT_MAX_REQUEST_BODY_SIZE]
