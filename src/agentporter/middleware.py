"""Security middleware enforcing host validation, rate limits, payload limits, and auth."""

import logging
from starlette.types import ASGIApp, Scope, Receive, Send, Message
from starlette.responses import JSONResponse
from agentporter.auth import verify_api_key, is_host_allowed, RateLimiter

logger = logging.getLogger("agentporter.middleware")


class SecurityMiddleware:
    """ASGI middleware enforcing API-key auth and bounded HTTP ingress."""

    def __init__(
        self,
        app: ASGIApp,
        api_key: str | list[str],
        allowed_hosts: list[str],
        header_name: str = "X-AgentPorter-Key",
<<<<<<< HEAD
        legacy_header_name: str = "",
        rate_limiter: RateLimiter = None,
=======
        legacy_header_name: str = "X-M3-MCP-Key",
        rate_limiter: RateLimiter | None = None,
>>>>>>> origin/main
        max_payload_bytes: int = 10 * 1024 * 1024,
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

<<<<<<< HEAD
    def _log_rejection_diagnostic(self, headers: dict, reason: str) -> None:
        raw_header = headers.get(self.header_bytes)
        if raw_header is None and self.legacy_header_bytes:
            raw_header = headers.get(self.legacy_header_bytes)
=======
    def _log_rejection_diagnostic(self, headers: dict, reason: str, provided_key: str = ""):
        header_keys = [k.decode("latin-1", errors="replace") for k in headers.keys()]
        auth_raw = headers.get(b"authorization", b"").decode("utf-8", errors="replace")

>>>>>>> origin/main
        logger.warning(
            "AUTH_REJECTION: reason=%s | headers_received=%s | auth_header_len=%d | auth_starts_bearer=%s | provided_key_len=%d",
            reason,
<<<<<<< HEAD
            raw_header is not None,
            len(raw_header) if raw_header is not None else 0,
=======
            header_keys,
            len(auth_raw),
            auth_raw.lower().startswith("bearer "),
            len(provided_key),
>>>>>>> origin/main
        )

    async def __call__(self, scope: Scope, receive: Receive, send: Send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
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

<<<<<<< HEAD
        raw_header = headers.get(self.header_bytes)
        if raw_header is None and self.legacy_header_bytes:
            raw_header = headers.get(self.legacy_header_bytes)
        provided_key = (
            raw_header.decode("utf-8", errors="replace") if raw_header is not None else ""
        )
        if not verify_api_key(provided_key, self.api_key):
            self._log_rejection_diagnostic(headers, "invalid_or_missing_key")
            await JSONResponse(
                {"error": "Unauthorized: invalid or missing API key header"},
                status_code=401,
            )(scope, receive, send)
            return

        # Buffer request bodies only for methods that can carry MCP payloads. This
        # enforces the ceiling even when Content-Length is absent/chunked and
        # ensures rejection happens before the downstream app starts a response.
        if scope.get("method", "GET").upper() in {"POST", "PUT", "PATCH"}:
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

            await self.app(scope, replay_receive, send)
            return

=======
        # 4. Publicly accessible endpoints (protected by host and rate limiting)
        public_paths = {"/health", "/openapi.json", "/docs", "/redoc"}
        if scope.get("path") in public_paths:
            if scope.get("path") == "/health":
                resp = JSONResponse({"status": "healthy", "service": "agentporter", "version": "1.0.0"})
                await resp(scope, receive, send)
                return
            else:
                await self.app(scope, receive, send)
                return

        # 5. API Key validation
        raw_header = headers.get(self.header_bytes)
        if raw_header is None and self.legacy_header_bytes:
            raw_header = headers.get(self.legacy_header_bytes)
            
        provided_key = raw_header.decode("utf-8", errors="replace") if raw_header is not None else ""

        if not provided_key:
            auth_header = headers.get(b"authorization", b"").decode("utf-8", errors="replace")
            if auth_header.lower().startswith("bearer "):
                provided_key = auth_header[7:].strip()

        if not verify_api_key(provided_key, self.api_key):
            self._log_rejection_diagnostic(headers, "invalid_or_missing_key", provided_key)
            resp = JSONResponse({"error": "Unauthorized: invalid or missing API key header"}, status_code=401)
            await resp(scope, receive, send)
            return

        # 6. Rewrite root path '/' to '/mcp' for Streamable HTTP compatibility (e.g. Copilot Studio)
        if scope.get("path") in ("/", ""):
            scope["path"] = "/mcp"
            if "raw_path" in scope:
                scope["raw_path"] = b"/mcp"

        # Authorized, continue downstream
>>>>>>> origin/main
        await self.app(scope, receive, send)

