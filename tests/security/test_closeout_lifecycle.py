"""Bounded synthetic socket regressions for response lifetime and half-close."""
import socket
import threading
import time

import pytest
from agentporter.agents import development_egress as egress
from agentporter.agents import provider_egress as provider


@pytest.mark.parametrize('headroom', [False, True])
def test_half_closed_client_receives_delayed_complete_stream(headroom):
    client, downstream = socket.socketpair()
    upstream, server = socket.socketpair()
    stop = threading.Event()
    def run():
        try:
            if headroom: egress._headroom_response(downstream, upstream, stop)
            else: egress._relay(downstream, upstream, stop)
        finally:
            downstream.close(); upstream.close()
    thread = threading.Thread(target=run)
    thread.start()
    try:
        client.shutdown(socket.SHUT_WR)
        if not headroom:
            server.settimeout(2)
            assert server.recv(1) == b''
        time.sleep(0.05)
        server.sendall(b'HTTP/1.1 200 OK\r\n\r\nfirst')
        time.sleep(0.05)
        server.sendall(b'-last')
        server.shutdown(socket.SHUT_WR)
        client.settimeout(2)
        data = b''
        while block := client.recv(1024): data += block
        assert data == b'HTTP/1.1 200 OK\r\n\r\nfirst-last'
    finally:
        stop.set();client.close();server.close();thread.join(2)
    assert not thread.is_alive()


@pytest.mark.parametrize('cancel', [False, True])
def test_stall_and_explicit_cancellation_are_bounded(monkeypatch, cancel):
    client, downstream = socket.socketpair(); upstream, server = socket.socketpair()
    stop = threading.Event()
    monkeypatch.setattr(egress, 'IDLE_TIMEOUT', 0.05 if not cancel else 300)
    thread = threading.Thread(target=egress._headroom_response, args=(downstream,upstream,stop))
    thread.start()
    if cancel: stop.set()
    thread.join(1.5)
    for item in (client,downstream,upstream,server): item.close()
    assert not thread.is_alive()


def test_second_headroom_request_terminates_without_upstream_forwarding():
    client, downstream = socket.socketpair(); upstream, server = socket.socketpair()
    stop = threading.Event()
    thread = threading.Thread(target=egress._headroom_response,args=(downstream,upstream,stop))
    thread.start();client.sendall(b'GET /admin HTTP/1.1\r\n\r\n');thread.join(1)
    server.settimeout(0.05)
    with pytest.raises(socket.timeout): server.recv(1)
    for item in (client,downstream,upstream,server): item.close()
    assert not thread.is_alive()


def test_reasoning_idle_policy_is_longer_but_finite():
    assert 60 < egress.IDLE_TIMEOUT < egress.RELAY_TIMEOUT <= 900


def test_response_survives_a_simulated_gap_longer_than_old_timeout(monkeypatch):
    real_clock=time.monotonic
    offset=[0]
    monkeypatch.setattr(egress.time,'monotonic',lambda:real_clock()+offset[0])
    client,downstream=socket.socketpair();upstream,server=socket.socketpair();stop=threading.Event()
    thread=threading.Thread(target=egress._headroom_response,args=(downstream,upstream,stop))
    thread.start()
    try:
        time.sleep(.02);offset[0]=65
        time.sleep(.55)
        assert thread.is_alive(),'Old 60-second cutoff still truncates reasoning'
        server.sendall(b'complete-after-reasoning');server.shutdown(socket.SHUT_WR)
        client.settimeout(1)
        assert client.recv(1024)==b'complete-after-reasoning'
    finally:
        stop.set();thread.join(1)
        for item in (client,downstream,upstream,server):item.close()
    assert not thread.is_alive()


def test_wei_free_only_route_and_payload():
    import json
    rules = provider.provider_rules('wei')
    assert provider.operation_allowed(rules,'opencode.ai','POST','/inference/openai/v1/chat/completions')
    assert not provider.operation_allowed(rules,'opencode.ai','POST','/inference/go/openai/v1/chat/completions')
    header = b'POST /inference/openai/v1/chat/completions HTTP/1.1\r\nHost: opencode.ai'
    provider.validate_payload(header,json.dumps({'model':'glm-5.3-flash-free','messages':[]}).encode(),'opencode.ai')
    with pytest.raises(PermissionError,match='free models'):
        provider.validate_payload(header,b'{"model":"glm-5.3-flash","messages":[]}', 'opencode.ai')
    with pytest.raises(PermissionError):
        provider.validate_payload(header,b'{"model":"glm-5.3-flash-free","tools":[{"type":"mcp","server_url":"https://example.com"}]}','opencode.ai')
