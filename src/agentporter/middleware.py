"""Security middleware enforcing host validation, rate limits, payload limits, and auth."""

import logging
import hmac
from starlette.types import ASGIApp, Scope, Receive, Send, Message
from starlette.responses import JSONResponse
from agentporter.auth import verify_api_key, is_host_allowed, RateLimiter
from agentporter.client_policy import PRINCIPAL

logger = logging.getLogger("agentporter.middleware")


class SecurityMiddleware:
    """ASGI middleware enforcing API-key auth and bounded HTTP ingress."""

    def __init__(
        self,
        app: ASGIApp,
        api_key: str,
        allowed_hosts: list[str],
        header_name: str = "X-AgentPorter-Key",
        legacy_header_name: str = "",
        rate_limiter: RateLimiter = None,
        max_payload_bytes: int = 10 * 1024 * 1024,
        delegation_relay_key: str | None = None,
        internal_client_key: str | None = None,
    ):
        self.app = app
        self.api_key = api_key
        self.allowed_hosts = allowed_hosts
        self.header_bytes = header_name.lower().encode("latin-1")
        self.legacy_header_bytes = (
            legacy_header_name.lower().encode("latin-1") if legacy_header_name else None
        )
        self.rate_limiter = rate_limiter or RateLimiter()
        self.max_payload_bytes = max_payload_bytes
        self.delegation_relay_key = delegation_relay_key
        if internal_client_key and internal_client_key in {api_key, delegation_relay_key}:
            raise PermissionError('Internal, public and relay credentials must differ')
        self.internal_client_key = internal_client_key

    async def _call_client(self, scope, receive, send, principal):
        token = PRINCIPAL.set(principal)
        try:
            await self.app(scope, receive, send)
        finally:
            PRINCIPAL.reset(token)

    def _log_rejection_diagnostic(self, headers: dict, reason: str) -> None:
        raw_header = headers.get(self.header_bytes)
        if raw_header is None and self.legacy_header_bytes:
            raw_header = headers.get(self.legacy_header_bytes)
        logger.warning(
            "AUTH_REJECTION: reason=%s | key_present=%s | header_len=%d",
            reason,
            raw_header is not None,
            len(raw_header) if raw_header is not None else 0,
        )

    async def __call__(self, scope: Scope, receive: Receive, send: Send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        # Health and the generated schema are intentionally public. Clients
        # must be able to probe/import the gateway before sending the API key;
        # the OpenAPI document declares BearerAuth for every protected route.
        if scope.get("path") in {
            "/health",
            "/openapi.json",
            "/docs",
            "/docs/",
            "/docs/oauth2-redirect",
            "/redoc",
        }:
            await self.app(scope, receive, send)
            return

        # This route uses a SEPARATE, narrow-scoped credential, not the full
        # AgentPorter API key. Never fall back to ordinary API authorization.
        if scope.get("path") == "/internal/delegation/v1":
            headers = dict(scope.get("headers", []))
            client = scope.get("client")
            loopback = client is not None and client[0] in {"127.0.0.1", "::1"}
            provided = headers.get(b"authorization", b"")
            expected = ("Bearer " + self.delegation_relay_key).encode("ascii") if self.delegation_relay_key else b""
            if (not loopback or not expected or not hmac.compare_digest(provided, expected)):
                await JSONResponse({"error": "Unauthorized delegation relay"}, status_code=401)(
                    scope, receive, send)
                return
            if scope.get("method") != "POST":
                await JSONResponse({"error": "Method not allowed"}, status_code=405)(
                    scope, receive, send)
                return
            if not self.rate_limiter.is_allowed(client[0]):
                await JSONResponse({"error": "Delegation rate limit exceeded"}, status_code=429)(
                    scope, receive, send)
                return
            # Reject unknown-length/chunked bodies too; never read more than
            # the fixed maximum independently of the normal API size ceiling.
            data = bytearray()
            while True:
                message = await receive()
                if message["type"] != "http.request":
                    return
                data.extend(message.get("body", b""))
                if len(data) > 32768:
                    await JSONResponse({"error": "Relay request too large"}, status_code=413)(
                        scope, receive, send)
                    return
                if not message.get("more_body", False):
                    break
            sent = False
            async def relay_receive():
                nonlocal sent
                if not sent:
                    sent = True
                    return {"type": "http.request", "body": bytes(data), "more_body": False}
                return {"type": "http.disconnect"}
            await self._call_client(scope, relay_receive, send, 'internal')
            return

        headers = dict(scope.get("headers", []))

        host = headers.get(b"host", b"").decode("utf-8", errors="replace")
        if not is_host_allowed(host, self.allowed_hosts):
            self._log_rejection_diagnostic(headers, "unauthorized_host")
            await JSONResponse(
                {"error": "Forbidden: Host header not allowed"}, status_code=403
            )(scope, receive, send)
            return

        client = scope.get("client")
        client_ip = client[0] if client else "unknown"
        if not self.rate_limiter.is_allowed(client_ip):
            self._log_rejection_diagnostic(headers, "rate_limit_exceeded")
            await JSONResponse(
                {"error": "Too Many Requests: Rate limit exceeded"}, status_code=429
            )(scope, receive, send)
            return

        content_length_str = headers.get(b"content-length", b"").decode(
            "utf-8", errors="replace"
        )
        if content_length_str.isdigit() and int(content_length_str) > self.max_payload_bytes:
            await JSONResponse({"error": "Payload Too Large"}, status_code=413)(
                scope, receive, send
            )
            return

        raw_header = headers.get(self.header_bytes)
        if raw_header is None and self.legacy_header_bytes:
            raw_header = headers.get(self.legacy_header_bytes)
        if raw_header is None:
            raw_header = headers.get(b"authorization")
        provided_key = (
            raw_header.decode("utf-8", errors="replace") if raw_header is not None else ""
        )
        internal = bool(self.internal_client_key and verify_api_key(provided_key, self.internal_client_key))
        if internal and (client_ip not in {'127.0.0.1', '::1'} or any(
                name in headers for name in (b'forwarded', b'x-forwarded-for', b'x-forwarded-host', b'x-real-ip'))):
            await JSONResponse({'error': 'Internal credential requires direct local access'}, status_code=401)(scope, receive, send)
            return
        if not internal and not verify_api_key(provided_key, self.api_key):
            self._log_rejection_diagnostic(headers, "invalid_or_missing_key")
            await JSONResponse(
                {"error": "Unauthorized: invalid or missing API key header"},
                status_code=401,
            )(scope, receive, send)
            return

        principal = 'internal' if internal else 'public'

        if scope.get("method", "GET").upper() in {"POST", "PUT", "PATCH"}:
            # The MCP SDK's RequestBodyLimitMiddleware enforces a byte cap
            # before Starlette's response machinery, including chunked
            # requests without Content-Length. Raising from downstream
            # receive() here would be misreported as HTTP 500 by Starlette.
            # Do not prebuffer or wait for EOF in this outer middleware.
            if scope.get("path") in {"/mcp", "/mcp/"}:
                await self._call_client(scope, receive, send, principal)
                return

            # Keep buffering for REST requests so the size ceiling is enforced
            # before a downstream handler starts its response.
            buffered: list[Message] = []
            total = 0
            while True:
                message = await receive()
                buffered.append(message)
                if message["type"] == "http.request":
                    total += len(message.get("body", b""))
                    if total > self.max_payload_bytes:
                        await JSONResponse({"error": "Payload Too Large"}, status_code=413)(
                            scope, receive, send
                        )
                        return
                    if not message.get("more_body", False):
                        break
                elif message["type"] == "http.disconnect":
                    break

            index = 0

            async def replay_receive() -> Message:
                nonlocal index
                if index < len(buffered):
                    msg = buffered[index]
                    index += 1
                    return msg
                return {"type": "http.request", "body": b"", "more_body": False}

            await self._call_client(scope, replay_receive, send, principal)
            return

        await self._call_client(scope, receive, send, principal)
