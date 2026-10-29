"""Public-only egress checks; tests never contact production or public APIs."""

import os
from pathlib import Path
import shutil
import socket
import subprocess
import threading

import pytest

from agentporter.agents import development_egress as egress


@pytest.mark.parametrize("address", [
    "127.0.0.1", "0.0.0.0", "10.0.0.1", "192.168.1.2", "172.16.0.1",
    "169.254.169.254", "100.64.0.1", "224.0.0.1", "255.255.255.255",
    "192.0.2.1", "::1", "::", "fc00::1", "fe80::1", "ff02::1",
    "::ffff:8.8.8.8", "2001:db8::1", "2002:0a00:0001::1",
    "64:ff9b::a9fe:a9fe", "invalid",
])
def test_nonpublic_addresses_denied(address):
    assert not egress._public_address(address)


@pytest.mark.parametrize('port', [8787, 9787])
def test_headroom_endpoint_is_a_fixed_service_capability(tmp_path, monkeypatch, port):
    """A model request reaches only the fixed Headroom destination."""
    private = tmp_path / 'private'
    private.mkdir(mode=0o700)
    upstream, service = socket.socketpair()
    selected = []
    received = []

    def connect(address, timeout):
        selected.append(address)
        return upstream

    def respond():
        received.append(service.recv(4096))
        service.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK')
        service.close()

    monkeypatch.setattr(egress.socket, 'create_connection', connect)
    thread = threading.Thread(target=respond)
    thread.start()
    try:
        with egress.HeadroomEgress(private / 'headroom.sock', port=port):
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
                client.settimeout(3)
                client.connect(str(private / 'headroom.sock'))
                client.sendall(f'POST /v1/responses HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nContent-Length: 2\r\n\r\n{{}}'.encode())
                assert client.recv(4096).endswith(b'OK')
        thread.join(timeout=3)
        assert not thread.is_alive()
        assert selected == [('127.0.0.1', port)]
        assert received[0].startswith(b'POST /v1/responses HTTP/1.1\r\n')
        assert b'connection: close\r\n' in received[0]
    finally:
        upstream.close()
        service.close()


@pytest.mark.parametrize('port', [22, 8765, 8876, True, '8787'])
def test_headroom_cannot_select_other_loopback_services(tmp_path, port):
    with pytest.raises(PermissionError, match='Unapproved Headroom port'):
        egress.HeadroomEgress(tmp_path / 'denied.sock', port=port)


def test_bcc_headroom_rejects_asgard_authority():
    left, right = socket.socketpair()
    try:
        left.sendall(b'GET /v1/models HTTP/1.1\r\nHost: 127.0.0.1:9787\r\n\r\n')
        with pytest.raises(PermissionError):
            egress._headroom_request(right, port=8787)
    finally:
        left.close()
        right.close()


@pytest.mark.parametrize('payload', [
    b'POST /admin/upstream HTTP/1.1\r\nHost: 127.0.0.1:9787\r\n\r\n',
    b'GET /stats HTTP/1.1\r\nHost: 127.0.0.1:9787\r\n\r\n',
    b'CONNECT 127.0.0.1:22 HTTP/1.1\r\nHost: 127.0.0.1:9787\r\n\r\n',
    b'POST http://127.0.0.1:22/v1/responses HTTP/1.1\r\nHost: 127.0.0.1:9787\r\n\r\n',
    b'POST /v1/responses HTTP/1.1\r\nHost: 127.0.0.1:9787\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n',
    b'POST /v1/responses HTTP/1.1\r\nHost: 127.0.0.1:9787\r\nContent-Length: 0\r\n\r\nGET /stats HTTP/1.1\r\n\r\n',
])
def test_headroom_control_plane_and_ambiguous_requests_denied(payload):
    left, right = socket.socketpair()
    try:
        left.sendall(payload)
        with pytest.raises((ValueError, PermissionError)):
            egress._headroom_request(right)
    finally:
        left.close()
        right.close()


@pytest.mark.parametrize("address", ["8.8.8.8", "1.1.1.1", "2606:4700:4700::1111"])
def test_public_addresses_classified(address):
    assert egress._public_address(address)


def _parse(payload):
    left, right = socket.socketpair()
    try:
        left.sendall(payload)
        left.shutdown(socket.SHUT_WR)
        return egress._read_connect(right)
    finally:
        left.close()
        right.close()


def test_connect_parser_retains_first_tls_bytes():
    assert _parse(b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n\x16\x03") == ("example.com", b"\x16\x03")


@pytest.mark.parametrize("payload", [
    b"GET https://example.com/ HTTP/1.1\r\n\r\n",
    b"CONNECT example.com:80 HTTP/1.1\r\n\r\n",
    b"CONNECT user:pass@example.com:443 HTTP/1.1\r\n\r\n",
    b"CONNECT example.com:443 HTTP/1.1\r\n x-folded: value\r\n\r\n",
    b"CONNECT example.com:443 HTTP/1.1\r\nX-Test: \x00\r\n\r\n",
    b"CONNECT example.com:443 HTTP/1.1\r\nX-Test: " + b"x" * 8192 + b"\r\n\r\n",
    b"CONNECT example.com:443 HTTP/1.1\r\n",
])
def test_malformed_or_unbounded_headers_denied(payload):
    with pytest.raises(ValueError):
        _parse(payload)


def test_mixed_dns_answers_are_all_rejected(monkeypatch):
    monkeypatch.setattr(egress.socket, "getaddrinfo", lambda *_args, **_kwargs: [
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", 443)),
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 443)),
    ])
    with pytest.raises(PermissionError):
        egress._connect_public("mixed.example")


def test_public_connection_uses_pinned_numeric_address(monkeypatch):
    calls = []
    class FakeSocket:
        def settimeout(self, timeout):
            assert 0 < timeout <= egress.CONNECT_TIMEOUT
        def connect(self, address):
            calls.append(address)
    monkeypatch.setattr(egress.socket, "getaddrinfo", lambda *_args, **_kwargs: [
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", 443)),
    ])
    monkeypatch.setattr(egress.socket, "socket", lambda *_args: FakeSocket())
    egress._connect_public("public.example")
    assert calls == [("8.8.8.8", 443)]


def _request(path, payload):
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
        client.settimeout(3)
        client.connect(str(path))
        client.sendall(payload)
        return client.recv(8192)


@pytest.mark.parametrize("host", ["localhost", "127.0.0.1", "169.254.169.254", "100.64.0.1", "[::1]"])
def test_real_unix_endpoint_denies_private_destinations(tmp_path, host):
    tmp_path.chmod(0o700)
    path = tmp_path / "egress.sock"
    with egress.PublicEgress(path):
        assert path.stat().st_mode & 0o777 == 0o600
        response = _request(path, f"CONNECT {host}:443 HTTP/1.1\r\n\r\n".encode())
        assert response.startswith(b"HTTP/1.1 403")
    assert not path.exists()


def test_real_endpoint_refuses_plain_http(tmp_path):
    tmp_path.chmod(0o700)
    with egress.PublicEgress(tmp_path / "egress.sock"):
        response = _request(tmp_path / "egress.sock", b"GET http://example.com/ HTTP/1.1\r\n\r\n")
        assert response.startswith(b"HTTP/1.1 400")


def test_real_endpoint_relays_opaque_bytes_and_closes(tmp_path, monkeypatch):
    tmp_path.chmod(0o700)
    upstream, backend = socket.socketpair()
    monkeypatch.setattr(egress, "_connect_public", lambda host: upstream)
    path = tmp_path / "egress.sock"
    with egress.PublicEgress(path) as proxy:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
            client.settimeout(2)
            backend.settimeout(2)
            client.connect(str(path))
            client.sendall(b"CONNECT example.com:443 HTTP/1.1\r\n\r\n")
            assert client.recv(8192).startswith(b"HTTP/1.1 200")
            client.sendall(b"opaque TLS bytes")
            assert backend.recv(8192) == b"opaque TLS bytes"
            backend.sendall(b"opaque reply")
            assert client.recv(8192) == b"opaque reply"
        backend.close()
    assert proxy._accept_thread is not None
    assert not proxy._accept_thread.is_alive()
    assert not path.exists()


def test_close_interrupts_incomplete_header(tmp_path):
    tmp_path.chmod(0o700)
    proxy = egress.PublicEgress(tmp_path / "egress.sock").start()
    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        client.connect(str(proxy.socket_path))
        client.sendall(b"CONNECT")
        proxy.close()
        assert not proxy._accept_thread.is_alive()
        assert all(not thread.is_alive() for thread in proxy._threads)
    finally:
        client.close()
        proxy.close()


def test_slow_connect_cannot_add_upstream_after_proxy_close(tmp_path, monkeypatch):
    tmp_path.chmod(0o700)
    upstream, backend = socket.socketpair()
    entered = threading.Event()
    release = threading.Event()
    def delayed_connect(_host):
        entered.set()
        assert release.wait(timeout=5)
        return upstream
    monkeypatch.setattr(egress, "_connect_public", delayed_connect)
    proxy = egress.PublicEgress(tmp_path / "egress.sock").start()
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
            client.connect(str(proxy.socket_path))
            client.sendall(b"CONNECT example.com:443 HTTP/1.1\r\n\r\n")
            assert entered.wait(timeout=2)
            threads = list(proxy._threads)
            proxy.close()
            release.set()
            for thread in threads:
                thread.join(timeout=2)
                assert not thread.is_alive()
            backend.settimeout(2)
            assert backend.recv(1) == b""
            assert not proxy._connections
    finally:
        release.set()
        backend.close()
        proxy.close()


def test_nonprivate_directory_refused(tmp_path):
    tmp_path.chmod(0o755)
    with pytest.raises(PermissionError):
        egress.PublicEgress(tmp_path / "egress.sock").start()


def test_existing_socket_path_not_replaced(tmp_path):
    tmp_path.chmod(0o700)
    path = tmp_path / "egress.sock"
    path.write_text("existing file")
    with pytest.raises(OSError):
        egress.PublicEgress(path).start()
    assert path.read_text() == "existing file"


def test_standalone_bridge_executes_worker_and_uses_only_local_proxy(tmp_path):
    tmp_path.chmod(0o700)
    path = tmp_path / "egress.sock"
    helper = str(Path(egress.__file__).resolve())
    worker = (
        "import os,socket,urllib.parse; "
        "p=urllib.parse.urlsplit(os.environ['HTTPS_PROXY']); "
        "assert p.hostname=='127.0.0.1'; "
        "assert 'ALL_PROXY' not in os.environ; "
        "assert os.environ['NO_PROXY']=='127.0.0.1,localhost,::1'; "
        "assert os.environ['no_proxy']==os.environ['NO_PROXY']; "
        "s=socket.create_connection((p.hostname,p.port),2); "
        "s.sendall(b'CONNECT 127.0.0.1:443 HTTP/1.1\\r\\n\\r\\n'); "
        "assert s.recv(8192).startswith(b'HTTP/1.1 403'); print('bridge verified')"
    )
    with egress.PublicEgress(path):
        result = subprocess.run([
            "/usr/bin/python3", helper, "bridge", "--socket", str(path), "--port", "0", "--",
            "/usr/bin/python3", "-c", worker,
        ], env={"PATH": "/usr/bin:/bin", "ALL_PROXY": "http://invalid", "NO_PROXY": "*"},
            text=True, capture_output=True, timeout=10)
    assert result.returncode == 0, result.stderr
    assert result.stdout == "bridge verified\n"


def test_installed_opencode_standalone_admin_uses_namespace_loopback(tmp_path):
    """Optional installed-CLI smoke: no login, host HOME, or model inference."""
    executable = shutil.which("opencode")
    if not executable or not shutil.which("bwrap"):
        pytest.skip("installed OpenCode and Bubblewrap required for external CLI smoke")
    executable = Path(executable).resolve()
    with executable.open("rb") as stream:
        if stream.read(4) != b"\x7fELF":
            pytest.skip("standalone native OpenCode executable required")
    tmp_path.chmod(0o700)
    home = tmp_path / "empty-home"
    home.mkdir(mode=0o700)
    helper = str(Path(egress.__file__).resolve())
    command = ["/usr/bin/bwrap", "--unshare-all", "--die-with-parent", "--new-session", "--clearenv"]
    for path in ("/usr", "/bin", "/lib", "/lib64", "/etc/ssl/certs"):
        if Path(path).exists():
            command += ["--ro-bind", path, path]
    command += [
        "--ro-bind", str(executable), "/opt/opencode",
        "--ro-bind", helper, "/opt/development_egress.py",
        "--ro-bind", str(tmp_path / "egress.sock"), "/run/agentporter-egress.sock",
        "--bind", str(home), "/home/worker", "--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp",
        "--setenv", "HOME", "/home/worker", "--setenv", "PATH", "/usr/bin:/bin",
        "--setenv", "LANG", "C.UTF-8", "--setenv", "NO_PROXY", "*", "--setenv", "no_proxy", "*",
        "--chdir", "/tmp", "--", "/usr/bin/python3", "-I", "-S", "/opt/development_egress.py",
        "bridge", "--socket", "/run/agentporter-egress.sock", "--port", "18765", "--",
        "/opt/opencode", "auth", "list", "--standalone",
    ]
    with egress.PublicEgress(tmp_path / "egress.sock"):
        version = subprocess.run(command[:-4] + ["/opt/opencode", "--version"],
                                 env={"PATH": "/usr/bin:/bin"}, text=True,
                                 capture_output=True, timeout=10)
        assert version.returncode == 0, version.stderr
        if not version.stdout.strip().split()[-1].lstrip("v").startswith("2."):
            pytest.skip("OpenCode v2 standalone administrative smoke required")
        result = subprocess.run(command, env={"PATH": "/usr/bin:/bin"}, text=True,
                                capture_output=True, timeout=20)
    assert result.returncode == 0, result.stderr
    assert "No authenticated integrations" in result.stdout
    assert "UnsupportedContentType" not in result.stderr
