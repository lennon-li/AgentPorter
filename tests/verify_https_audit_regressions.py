"""Standalone no-network regression checks for Prof's HTTPS audit findings."""
from __future__ import annotations

import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from agentporter.scoped_https import ScopedPublicHTTPS, ScopedPublicHTTPSPolicy

APPROVED = """version: 1
workspaces:
  cranary:
    hosts: [api.github.com]
    methods: [GET, HEAD]
    max_response_bytes: 262144
    timeout_seconds: 15
"""


class Response:
    status = 200
    reason = "OK\r\nSet-Cookie: injected"
    length = 0

    def __init__(self, headers):
        self.headers = headers

    def getheaders(self):
        return self.headers

    def read(self, n):
        return b""


class Connection:
    def __init__(self, response):
        self.response = response
        self.closed = False

    def request(self, *args, **kwargs):
        pass

    def getresponse(self):
        return self.response

    def close(self):
        self.closed = True


def denied(operation, exception=PermissionError):
    try:
        operation()
    except exception:
        return
    raise AssertionError(f"Expected {exception.__name__}")


with tempfile.TemporaryDirectory() as base:
    directory = Path(base) / "private"
    directory.mkdir(mode=0o700)
    policy_path = directory / "public-https.yaml"
    policy_path.write_text(APPROVED)
    policy_path.chmod(0o600)
    policy = ScopedPublicHTTPSPolicy(directory)

    assert policy.authorize("cranary", "GET", "https://api.github.com/?safe=value")
    for url in (
        "https://api.github.com/?%74oken=secret",
        "https://api.github.com/?api%5fkey=secret",
        "https://api.github.com/?%70assword=secret",
        "https://api.github.com/?foo%3dtoken=secret",
    ):
        denied(lambda url=url: policy.authorize("cranary", "GET", url))
    print("PASS: encoded query credential names")

    conn = Connection(Response([("Content-Type", "text/plain\r\nSet-Cookie: bad")]))
    broker = ScopedPublicHTTPS(policy, connection_factory=lambda host, timeout: conn)
    denied(lambda: broker.run("cranary", ["curl", "-sSI", "https://api.github.com/"]), ValueError)
    assert conn.closed
    print("PASS: HEAD control characters denied")

    conn = Connection(Response([]))
    broker = ScopedPublicHTTPS(policy, connection_factory=lambda host, timeout: conn)
    result = broker.run("cranary", ["curl", "-sSI", "https://api.github.com/"])
    assert "Set-Cookie" not in result["stdout"] and result["stdout"].startswith("HTTP/1.1 200")
    print("PASS: reason phrase not reflected")

    conn = Connection(Response([("ETag", "x" * 512)] * 600))
    broker = ScopedPublicHTTPS(policy, connection_factory=lambda host, timeout: conn)
    denied(lambda: broker.run("cranary", ["curl", "-sSI", "https://api.github.com/"]), ValueError)
    print("PASS: HEAD metadata aggregate limit")

    unsafe = Path(base) / "unsafe"
    unsafe.mkdir(mode=0o700)
    unsafe.chmod(0o777)
    child = unsafe / "operator"
    child.mkdir(mode=0o700)
    denied(lambda: ScopedPublicHTTPSPolicy(child))
    print("PASS: mutable ancestor rejected")

    link = Path(base) / "symlink"
    link.symlink_to(directory, target_is_directory=True)
    denied(lambda: ScopedPublicHTTPSPolicy(link), OSError)
    print("PASS: symlinked config directory rejected")

with tempfile.TemporaryDirectory() as base:
    original = Path(base) / "operator"
    original.mkdir(mode=0o700)
    policy_file = original / "public-https.yaml"
    policy_file.write_text(APPROVED)
    policy_file.chmod(0o600)
    saved = Path(base) / "original-pinned"
    read_policy = ScopedPublicHTTPSPolicy._read_policy

    def replace_then_read(self, directory_fd):
        original.rename(saved)
        original.mkdir(mode=0o700)
        swapped = original / "public-https.yaml"
        swapped.write_text(APPROVED.replace("api.github.com", "evil.example"))
        swapped.chmod(0o600)
        return read_policy(self, directory_fd)

    ScopedPublicHTTPSPolicy._read_policy = replace_then_read
    try:
        policy = ScopedPublicHTTPSPolicy(original)
        assert policy.authorize("cranary", "GET", "https://api.github.com/")[0] == "api.github.com"
        denied(lambda: policy.authorize("cranary", "GET", "https://evil.example/"))
    finally:
        ScopedPublicHTTPSPolicy._read_policy = read_policy
print("PASS: pinned directory resists rename-and-replace race")

print("PASS: all scoped HTTPS audit regression checks")
