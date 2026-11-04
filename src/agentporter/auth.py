"""Authentication and authorization utilities for AgentPorter."""

import hmac
import time
import logging
from fnmatch import fnmatch
from collections import defaultdict

logger = logging.getLogger("agentporter.auth")


def verify_api_key(provided_key: str, expected_key: str | list[str]) -> bool:
    """Perform constant-time comparison of the API key to prevent timing side-channels."""
    if not provided_key or not expected_key:
        return False
    keys = [expected_key] if isinstance(expected_key, str) else expected_key
    clean_prov = provided_key.strip()
    while clean_prov.lower().startswith("bearer "):
        clean_prov = clean_prov[7:].strip()
    clean_bytes = clean_prov.encode("utf-8")
    for k in keys:
        if k and hmac.compare_digest(clean_bytes, k.strip().encode("utf-8")):
            return True
    return False


def is_host_allowed(host_header: str, allowed_hosts: list[str]) -> bool:
    """Validate incoming Host header against allowed host patterns to prevent DNS rebinding."""
    if not host_header:
        return False
    host_clean = host_header.strip().lower()
    for pattern in allowed_hosts:
        pat_clean = pattern.lower()
        if fnmatch(host_clean, pat_clean):
            return True
        # Match host without port if pattern does not specify a port
        if ":" in host_clean and ":" not in pat_clean:
            hostname = host_clean.split(":", 1)[0]
            if fnmatch(hostname, pat_clean):
                return True
    return False


class RateLimiter:
    """Sliding-window per-client IP rate limiter with idle cleanup."""

    def __init__(self, max_requests: int = 120, window_seconds: float = 60.0):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.requests: dict[str, list[float]] = defaultdict(list)
        self._last_cleanup = time.time()

    def is_allowed(self, client_ip: str) -> bool:
        now = time.time()
        cutoff = now - self.window_seconds

        # Periodic cleanup of idle IPs every 60s
        if now - self._last_cleanup > 60.0:
            dead_ips = [ip for ip, reqs in self.requests.items() if not reqs or reqs[-1] <= cutoff]
            for ip in dead_ips:
                self.requests.pop(ip, None)
            self._last_cleanup = now

        reqs = self.requests[client_ip]
        self.requests[client_ip] = [t for t in reqs if t > cutoff]
        if len(self.requests[client_ip]) >= self.max_requests:
            return False
        self.requests[client_ip].append(now)
        return True
