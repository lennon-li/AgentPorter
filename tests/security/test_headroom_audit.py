"""Independent Headroom control-plane escape regressions; no live services."""
from __future__ import annotations

import threading
import json

import pytest

from agentporter.agents import development_egress as egress


@pytest.mark.parametrize("upgrade", [False, True])
def test_enforced_headroom_cannot_invoke_hosted_tools_or_opaque_upgrades(tmp_path, monkeypatch, upgrade):
    body = json.dumps({"tools": [{"type": "mcp", "server_url": "https://example.com"}]}).encode()
    if upgrade:
        payload = (b"GET /v1/responses HTTP/1.1\r\nHost: 127.0.0.1:9787\r\n"
                   b"Upgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\n"
                   b"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n")
    else:
        payload = (b"POST /v1/responses HTTP/1.1\r\nHost: 127.0.0.1:9787\r\nContent-Length: "
                   + str(len(body)).encode() + b"\r\n\r\n" + body)
    downstream = SyntheticSocket(payload)
    proxy = egress.HeadroomEgress(tmp_path / "relay.sock", enforce_provider_tools=True)
    calls = []
    monkeypatch.setattr(egress.socket, "create_connection", lambda *args, **kwargs: calls.append(args))
    assert proxy._slots.acquire(blocking=False)
    proxy._handle(downstream)
    assert downstream.closed and not calls
    assert proxy._slots.acquire(blocking=False)
    proxy._slots.release()


class SyntheticSocket:
    def __init__(self, incoming=b""):
        self.incoming = incoming
        self.sent = b""
        self.closed = False

    def settimeout(self, _timeout):
        pass

    def recv(self, size):
        result, self.incoming = self.incoming[:size], self.incoming[size:]
        return result

    def sendall(self, value):
        self.sent += value

    def close(self):
        self.closed = True


def test_enforced_headroom_rejects_encoded_body_before_opening_upstream(tmp_path, monkeypatch):
    payload = (b'POST /v1/responses HTTP/1.1\r\nHost: 127.0.0.1:9787\r\n'
               b'Content-Length: 2\r\nContent-Encoding: zstd\r\n\r\n{}')
    client = SyntheticSocket(payload)
    proxy = egress.HeadroomEgress(tmp_path / 'relay.sock', enforce_provider_tools=True)
    calls = []
    monkeypatch.setattr(egress.socket, 'create_connection', lambda *args, **kwargs: calls.append(args))
    assert proxy._slots.acquire(blocking=False)
    proxy._handle(client)
    assert client.closed and not calls
    assert proxy._slots.acquire(blocking=False)
    proxy._slots.release()


def request(method=b"GET", target=b"/v1/models", extra=b"", body=b""):
    return method + b" " + target + b" HTTP/1.1\r\nHost: 127.0.0.1:9787\r\n" + extra + b"\r\n" + body


@pytest.mark.parametrize("target", [
    b"/admin/upstream/settings", b"/admin", b"/metrics", b"/v1/../admin/upstream/settings",
    b"/v1/responses/../../admin/upstream/settings", b"/v1/responses?path=/admin",
    b"http://127.0.0.1:9787/admin", b"/%61dmin/upstream/settings", b"//admin/upstream/settings",
])
def test_control_plane_and_ambiguous_targets_are_denied(target):
    with pytest.raises((ValueError, PermissionError)):
        egress._headroom_request(SyntheticSocket(request(target=target)))


@pytest.mark.parametrize("extra", [
    b"Transfer-Encoding: chunked\r\n", b"Content-Length: 0\r\ncontent-length: 0\r\n",
    b"Host: 127.0.0.1:9787\r\n", b"Connection: keep-alive\r\n connection: upgrade\r\n",
    b"X-Test: good\x00bad\r\n", b"X-Test: good\r\n folded: bad\r\n",
])
def test_ambiguous_framing_is_denied(extra):
    with pytest.raises((ValueError, PermissionError)):
        egress._headroom_request(SyntheticSocket(request(extra=extra)))


def test_http_pipeline_to_admin_is_denied():
    payload = request() + request(target=b"/admin/upstream/settings")
    with pytest.raises((ValueError, PermissionError)):
        egress._headroom_request(SyntheticSocket(payload))


def test_approved_http_request_forces_connection_close():
    parsed, websocket = egress._headroom_request(SyntheticSocket(request(extra=b"Connection: keep-alive\r\n")))
    assert not websocket
    assert b"connection: close\r\n" in parsed
    assert b"keep-alive" not in parsed


HANDSHAKE = b"Upgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"


def test_upgrade_cannot_piggyback_admin_before_server_handshake():
    payload = request(target=b"/v1/responses", extra=HANDSHAKE) + request(target=b"/admin/upstream/settings")
    with pytest.raises((ValueError, PermissionError)):
        egress._headroom_request(SyntheticSocket(payload))


@pytest.mark.parametrize("response", [
    b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: keep-alive\r\n\r\n",
    b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: keep-alive\r\n\r\n",
    b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: invalid\r\n\r\n",
])
def test_nonupgrading_or_invalid_handshake_never_enters_duplex_relay(monkeypatch, response):
    downstream = SyntheticSocket(request(target=b"/v1/responses", extra=HANDSHAKE))
    upstream = SyntheticSocket(response)
    duplex = []
    destinations = []

    def connect(address, **kwargs):
        destinations.append(address)
        return upstream

    monkeypatch.setattr(egress.socket, "create_connection", connect)
    monkeypatch.setattr(egress, "_relay", lambda *_: duplex.append(True))
    monkeypatch.setattr(egress, "_headroom_response", lambda *_: None)
    endpoint = egress.HeadroomEgress("/tmp/synthetic-not-created.sock")
    endpoint._slots.acquire()
    endpoint._connections.add(downstream)
    endpoint._threads.add(threading.current_thread())
    endpoint._handle(downstream)
    assert destinations == [("127.0.0.1", 9787)]
    assert not duplex
    assert downstream.closed and upstream.closed
    assert b"/admin" not in upstream.sent


def test_valid_websocket_enters_duplex_only_after_upstream_upgrade(monkeypatch):
    downstream = SyntheticSocket(request(target=b"/v1/responses", extra=HANDSHAKE))
    handshake = b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n"
    upstream = SyntheticSocket(handshake)
    duplex = []
    monkeypatch.setattr(egress.socket, "create_connection", lambda *_args, **_kwargs: upstream)

    def after_handshake(*_):
        assert upstream.incoming == b""
        assert b"101 Switching Protocols" in downstream.sent
        duplex.append(True)

    monkeypatch.setattr(egress, "_relay", after_handshake)
    endpoint = egress.HeadroomEgress("/tmp/synthetic-not-created.sock")
    endpoint._slots.acquire()
    endpoint._handle(downstream)
    assert duplex == [True]
