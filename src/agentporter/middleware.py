"""Security middleware enforcing host validation, rate limits, payload limits, and auth."""

import hashlib
import logging
from starlette.types import ASGIApp, Scope, Receive, Send
from starlette.responses import JSONResponse
from agentporter.auth import verify_api_key, is_host_allowed, RateLimiter

logger = logging.getLogger("agentporter.middleware")


class SecurityMiddleware:
    """ASGI Middleware enforcing API key authentication, host validation, rate limiting, and size limits."""

    def __init__(
        self,
        app: ASGIApp,
        api_key: str,
        allowed_hosts: list[str],
        header_name: str = "X-AgentPorter-Key",
        legacy_header_name: str = "X-M3-MCP-Key",
        rate_limiter: RateLimiter = None,
        max_payload_bytes: int = 10 * 1024 * 1024,
    ):
        self.app = app
        self.api_key = api_key
        self.allowed_hosts = allowed_hosts
        self.header_bytes = header_name.lower().encode("latin-1")
        self.legacy_header_bytes = legacy_header_name.lower().encode("latin-1") if legacy_header_name else None
        self.rate_limiter = rate_limiter or RateLimiter()
        self.max_payload_bytes = max_payload_bytes

    def _log_rejection_diagnostic(self, headers: dict, reason: str):
        # Safely extract header info without logging key
        raw_header = headers.get(self.header_bytes)
        if raw_header is None and self.legacy_header_bytes:
            raw_header = headers.get(self.legacy_header_bytes)

        is_present = raw_header is not None
        val_len = len(raw_header) if is_present else 0

        logger.warning(
            "AUTH_REJECTION: reason=%s | key_present=%s | header_len=%d",
            reason,
            is_present,
            val_len,
        )

    async def __call__(self, scope: Scope, receive: Receive, send: Send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        headers = dict(scope.get("headers", []))

        # 1. Host header validation
        host = headers.get(b"host", b"").decode("utf-8", errors="replace")
        if not is_host_allowed(host, self.allowed_hosts):
            self._log_rejection_diagnostic(headers, f"unauthorized_host:{host}")
            resp = JSONResponse({"error": "Forbidden: Host header not allowed"}, status_code=403)
            await resp(scope, receive, send)
            return

        # 2. Rate limiting by client IP
        client = scope.get("client")
        client_ip = client[0] if client else "unknown"
        if not self.rate_limiter.is_allowed(client_ip):
            self._log_rejection_diagnostic(headers, f"rate_limit_exceeded:{client_ip}")
            resp = JSONResponse({"error": "Too Many Requests: Rate limit exceeded"}, status_code=429)
            await resp(scope, receive, send)
            return

        # 3. Content-Length payload check
        content_length_str = headers.get(b"content-length", b"").decode("utf-8", errors="replace")
        if content_length_str.isdigit():
            if int(content_length_str) > self.max_payload_bytes:
                self._log_rejection_diagnostic(headers, f"payload_too_large:{content_length_str}")
                resp = JSONResponse({"error": "Payload Too Large"}, status_code=413)
                await resp(scope, receive, send)
                return

        # 4. API Key validation
        raw_header = headers.get(self.header_bytes)
        if raw_header is None and self.legacy_header_bytes:
            raw_header = headers.get(self.legacy_header_bytes)

        provided_key = raw_header.decode("utf-8", errors="replace") if raw_header is not None else ""
        if not verify_api_key(provided_key, self.api_key):
            self._log_rejection_diagnostic(headers, "invalid_or_missing_key")
            resp = JSONResponse({"error": "Unauthorized: invalid or missing API key header"}, status_code=401)
            await resp(scope, receive, send)
            return

        # Authorized, continue downstream
        await self.app(scope, receive, send)
