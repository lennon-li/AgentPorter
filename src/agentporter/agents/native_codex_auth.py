"""Bounded WebSocket client for the owner's local Codex authentication daemon.

Only initialize and account/read RPCs are supported. No model turns, daemon
lifecycle operations, network listeners, extensions or credential logging.
"""
import base64
import hashlib
import json
import os
import struct

LIMIT = 2 * 1024 * 1024


class NativeAuthChannel:
    def __init__(self, channel):
        self.channel = channel
        self.reader = channel.makefile('rb')
        key = base64.b64encode(os.urandom(16)).decode()
        channel.sendall(('GET / HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\n'
            'Connection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: '+key+'\r\n\r\n').encode())
        try:
            first = self.reader.readline(8193)
            if first != b'HTTP/1.1 101 Switching Protocols\r\n':
                raise PermissionError('Native daemon WebSocket upgrade unavailable')
            headers = {}
            total = len(first)
            while True:
                line = self.reader.readline(8193)
                total += len(line)
                if not line or total > 16384:
                    raise PermissionError('Native daemon headers exceed bounds')
                if line == b'\r\n':
                    break
                name, value = line.decode('ascii').strip().split(':', 1)
                name = name.lower()
                if name in headers:
                    raise PermissionError('Duplicate native daemon header')
                headers[name] = value.strip()
            expected = base64.b64encode(hashlib.sha1((key+'258EAFA5-E914-47DA-95CA-C5AB0DC85B11').encode(), usedforsecurity=False).digest()).decode()
            if (headers.get('sec-websocket-accept') != expected
                    or headers.get('upgrade', '').lower() != 'websocket'
                    or headers.get('connection', '').lower() != 'upgrade'
                    or 'sec-websocket-extensions' in headers):
                raise PermissionError('Native daemon WebSocket handshake differs')
        except BaseException:
            self.reader.close()
            raise

    def close(self):
        self.reader.close()

    def _send(self, opcode, raw):
        if len(raw) > LIMIT:
            raise PermissionError('Native daemon request exceeds bounds')
        size = len(raw)
        prefix = bytes([0x80 | opcode])
        if size < 126:
            prefix += bytes([0x80 | size])
        elif size < 65536:
            prefix += bytes([0x80 | 126])+struct.pack('>H', size)
        else:
            prefix += bytes([0x80 | 127])+struct.pack('>Q', size)
        mask = os.urandom(4)
        masked = bytes(value ^ mask[i % 4] for i, value in enumerate(raw))
        self.channel.sendall(prefix+mask+masked)

    def send(self, value):
        self._send(1, json.dumps(value, allow_nan=False, separators=(',', ':')).encode())

    def _exact(self, count):
        raw = self.reader.read(count)
        if len(raw) != count:
            raise EOFError('Native daemon disconnected')
        return raw

    def receive(self):
        fragments = bytearray()
        started = False
        for _ in range(128):
            first, second = self._exact(2)
            opcode, final = first & 0x0f, bool(first & 0x80)
            if first & 0x70 or second & 0x80:
                raise PermissionError('Native daemon frame flags differ')
            size = second & 0x7f
            if size == 126:
                size, = struct.unpack('>H', self._exact(2))
            elif size == 127:
                size, = struct.unpack('>Q', self._exact(8))
            if size > LIMIT or len(fragments)+size > LIMIT:
                raise PermissionError('Native daemon frame exceeds bounds')
            if opcode >= 8 and (not final or size > 125):
                raise PermissionError('Invalid native daemon control frame')
            raw = self._exact(size)
            if opcode == 8:
                raise EOFError('Native daemon closed authentication channel')
            if opcode == 9:
                self._send(10, raw)
                continue
            if opcode == 10:
                continue
            if opcode not in {0, 1} or (opcode == 0) != started:
                raise PermissionError('Invalid native daemon message sequence')
            started = True
            fragments.extend(raw)
            if final:
                value = json.loads(fragments)
                if not isinstance(value, dict):
                    raise PermissionError('Invalid native daemon JSON-RPC object')
                return value
        raise PermissionError('Native daemon frame count exceeds bounds')

    def response(self, request_id):
        for _ in range(100):
            value = self.receive()
            if value.get('id') == request_id:
                if 'error' not in value and isinstance(value.get('result'), dict):
                    return value['result']
                break
        raise PermissionError('Native account operation unavailable')


def read_native_account(channel, *, refresh):
    """Use an already authenticated private daemon connection, without a turn."""
    client = NativeAuthChannel(channel)
    try:
        client.send({'id': 1, 'method': 'initialize', 'params': {'clientInfo': {
            'name': 'agentporter_bcc_auth', 'version': '1'}}})
        client.response(1)
        client.send({'method': 'initialized', 'params': {}})
        client.send({'id': 2, 'method': 'account/read', 'params': {'refreshToken': refresh}})
        result = client.response(2)
        if not isinstance(result.get('account'), dict) or result['account'].get('type') != 'chatgpt':
            raise PermissionError('Native account is not managed ChatGPT authentication')
    finally:
        client.close()
