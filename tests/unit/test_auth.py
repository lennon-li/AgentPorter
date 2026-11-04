"""Unit tests for authentication and host header validation."""

from agentporter.auth import verify_api_key, is_host_allowed, RateLimiter


def test_verify_api_key():
    assert not verify_api_key("", "secret123")
    assert not verify_api_key("wrong", "secret123")
    assert verify_api_key("secret123", "secret123")


def test_is_host_allowed():
    allowed = ["127.0.0.1", "127.0.0.1:*", "localhost", "*.trycloudflare.com"]
    assert is_host_allowed("127.0.0.1", allowed)
    assert is_host_allowed("127.0.0.1:8765", allowed)
    assert is_host_allowed("localhost:8000", allowed)
    assert is_host_allowed("tunnel-123.trycloudflare.com", allowed)
    assert not is_host_allowed("evil.attacker.com", allowed)
    assert not is_host_allowed("attacker.trycloudflare.com.evil.com", allowed)


def test_rate_limiter():
    limiter = RateLimiter(max_requests=3, window_seconds=10.0)
    ip = "127.0.0.1"
    assert limiter.is_allowed(ip)
    assert limiter.is_allowed(ip)
    assert limiter.is_allowed(ip)
    assert not limiter.is_allowed(ip)
