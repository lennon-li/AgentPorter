"""Development-only, public HTTPS CONNECT egress for network-isolated workers.

The host endpoint accepts a Unix socket, never an Internet-facing listener. DNS
resolution and address checks happen on the host; connections use the checked
numeric address. This file also runs standalone inside a worker namespace.
"""

from __future__ import annotations

import argparse
import base64
import contextlib
import ctypes
import hashlib
import ipaddress
import os
from pathlib import Path
import re
import selectors
import signal
import socket
import threading
import time

MAX_HEADER_BYTES = 8192
HEADER_TIMEOUT = 10.0
CONNECT_TIMEOUT = 10.0
IDLE_TIMEOUT = 300.0  # Bounded provider reasoning gap; owning job also has a deadline.
RELAY_TIMEOUT = 900.0
MAX_CONNECTIONS = 32


def _public_address(value: str) -> bool:
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False
    return bool(
        address.is_global
        and not address.is_multicast
        and not address.is_reserved
        and not address.is_unspecified
        and not address.is_loopback
        and not (isinstance(address, ipaddress.IPv6Address) and (
            address.ipv4_mapped or address.sixtofour or address.teredo
            or address in ipaddress.IPv6Network("64:ff9b::/96")
        ))
    )


def _read_connect(client: socket.socket) -> tuple[str, bytes]:
    """Read one bounded CONNECT header; retain any first TLS bytes."""
    client.settimeout(HEADER_TIMEOUT)
    data = bytearray()
    deadline = time.monotonic() + HEADER_TIMEOUT
    while b"\r\n\r\n" not in data:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise ValueError("CONNECT header timed out")
        client.settimeout(remaining)
        chunk = client.recv(min(4096, MAX_HEADER_BYTES + 1 - len(data)))
        if not chunk:
            raise ValueError("Incomplete CONNECT header")
        data.extend(chunk)
        boundary = data.find(b"\r\n\r\n")
        if (boundary < 0 and len(data) > MAX_HEADER_BYTES) or boundary + 4 > MAX_HEADER_BYTES:
            raise ValueError("CONNECT header too large")
    header, remainder = bytes(data).split(b"\r\n\r\n", 1)
    try:
        lines = header.decode("ascii").split("\r\n")
    except UnicodeDecodeError as exc:
        raise ValueError("Invalid CONNECT header") from exc
    match = re.fullmatch(r"CONNECT (\[[0-9a-fA-F:]+\]|[A-Za-z0-9.-]+):443 HTTP/1\.[01]", lines[0])
    if not match:
        raise ValueError("Only HTTPS CONNECT to port 443 is permitted")
    for line in lines[1:]:
        if not re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+:[\x20-\x7e\t]*", line):
            raise ValueError("Invalid CONNECT header")
    host = match.group(1).strip("[]")
    if len(host) > 253 or not host or host.startswith(".") or ".." in host:
        raise ValueError("Invalid destination")
    return host, remainder


def _connect_public(host: str) -> socket.socket:
    answers = socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)
    if not answers or any(not _public_address(answer[4][0]) for answer in answers):
        raise PermissionError("Destination is not public Internet")
    last_error: OSError | None = None
    deadline = time.monotonic() + CONNECT_TIMEOUT
    for family, kind, protocol, _, address in answers:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        upstream = socket.socket(family, kind, protocol)
        upstream.settimeout(remaining)
        try:
            upstream.connect(address)
            return upstream
        except OSError as exc:
            last_error = exc
            upstream.close()
    raise OSError("Public HTTPS connection failed") from last_error


def _relay(left: socket.socket, right: socket.socket, stop: threading.Event | None = None) -> None:
    """Preserve TCP half-close while draining the other direction, with bounds."""
    with selectors.DefaultSelector() as selector:
        selector.register(left, selectors.EVENT_READ, right)
        selector.register(right, selectors.EVENT_READ, left)
        left.settimeout(5.0)
        right.settimeout(5.0)
        last_activity = time.monotonic()
        started = last_activity
        while selector.get_map() and (stop is None or not stop.is_set()):
            if time.monotonic() - started >= RELAY_TIMEOUT:
                return
            if time.monotonic() - last_activity >= IDLE_TIMEOUT:
                return
            for key, _ in selector.select(timeout=0.5):
                chunk = key.fileobj.recv(65536)
                if not chunk:
                    selector.unregister(key.fileobj)
                    with contextlib.suppress(OSError):
                        key.data.shutdown(socket.SHUT_WR)
                    continue
                key.data.sendall(chunk)
                last_activity = time.monotonic()


class PublicEgress:
    """Per-job Unix CONNECT endpoint. Close it when the owning job finishes."""

    def __init__(self, socket_path: str | Path):
        self.socket_path = Path(socket_path)
        self._stop = threading.Event()
        self._listener: socket.socket | None = None
        self._accept_thread: threading.Thread | None = None
        self._threads: set[threading.Thread] = set()
        self._connections: set[socket.socket] = set()
        self._lock = threading.Lock()
        self._slots = threading.BoundedSemaphore(MAX_CONNECTIONS)

    def start(self) -> PublicEgress:
        if self._listener is not None or self._stop.is_set():
            raise RuntimeError("Egress endpoint cannot be restarted")
        parent = self.socket_path.parent
        if (not parent.is_dir() or parent.is_symlink()
                or parent.stat().st_uid != os.getuid() or parent.stat().st_mode & 0o077):
            raise PermissionError("Egress socket requires a private directory")
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            listener.bind(str(self.socket_path))
            os.chmod(self.socket_path, 0o600)
            listener.listen(MAX_CONNECTIONS)
            listener.settimeout(0.2)
        except BaseException:
            listener.close()
            raise
        self._listener = listener
        self._accept_thread = threading.Thread(target=self._accept, daemon=True, name="development-egress")
        self._accept_thread.start()
        return self

    def _accept(self) -> None:
        while not self._stop.is_set():
            try:
                client, _ = self._listener.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            if not self._slots.acquire(blocking=False):
                client.close()
                continue
            thread = threading.Thread(target=self._handle, args=(client,), daemon=True)
            with self._lock:
                if self._stop.is_set():
                    client.close()
                    self._slots.release()
                    return
                self._connections.add(client)
                self._threads.add(thread)
            thread.start()

    def _handle(self, client: socket.socket) -> None:
        upstream = None
        connected = False
        try:
            host, remainder = _read_connect(client)
            upstream = _connect_public(host)
            with self._lock:
                if self._stop.is_set():
                    return
                self._connections.add(upstream)
            client.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            connected = True
            if remainder:
                upstream.sendall(remainder)
            _relay(client, upstream, self._stop)
        except (ValueError, PermissionError, OSError) as exc:
            if not connected:
                status = b"403 Forbidden" if isinstance(exc, PermissionError) else b"400 Bad Request" if isinstance(exc, ValueError) else b"502 Bad Gateway"
                with contextlib.suppress(OSError):
                    client.sendall(b"HTTP/1.1 " + status + b"\r\nConnection: close\r\nContent-Length: 0\r\n\r\n")
        finally:
            with self._lock:
                self._connections.discard(client)
                self._connections.discard(upstream)
                self._threads.discard(threading.current_thread())
            client.close()
            if upstream is not None:
                upstream.close()
            self._slots.release()

    def close(self) -> None:
        self._stop.set()
        if self._listener is not None:
            self._listener.close()
        if self._accept_thread is not None:
            self._accept_thread.join(timeout=1.0)
        with self._lock:
            connections = list(self._connections)
            threads = list(self._threads)
        for connection in connections:
            with contextlib.suppress(OSError):
                connection.shutdown(socket.SHUT_RDWR)
            connection.close()
        deadline = time.monotonic() + 1.0
        for thread in threads:
            thread.join(timeout=max(0.0, deadline - time.monotonic()))
        if self._listener is not None:
            with contextlib.suppress(FileNotFoundError):
                self.socket_path.unlink()

    def __enter__(self) -> PublicEgress:
        return self.start()

    def __exit__(self, *_args) -> None:
        self.close()


def _bridge_connection(client: socket.socket, socket_path: str) -> None:
    with client, socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as upstream:
        try:
            upstream.settimeout(CONNECT_TIMEOUT)
            upstream.connect(socket_path)
            _relay(client, upstream)
        except OSError:
            pass


def _headroom_request(client: socket.socket) -> tuple[bytes, bool]:
    """Frame exactly one model API request; never expose Headroom admin APIs."""
    client.settimeout(5)
    data = b''
    while b'\r\n\r\n' not in data:
        block = client.recv(min(4096, MAX_HEADER_BYTES + 1 - len(data)))
        if not block or len(data) >= MAX_HEADER_BYTES:
            raise ValueError('Invalid Headroom request header')
        data += block
    head, remainder = data.split(b'\r\n\r\n', 1)
    if len(head) > MAX_HEADER_BYTES:
        raise ValueError('Headroom request header too large')
    lines = head.split(b'\r\n')
    method, target, version = lines[0].split(b' ')
    headers = {}
    for line in lines[1:]:
        name, value = line.split(b':', 1)
        name = name.lower()
        value = value.strip()
        if (not re.fullmatch(rb'[a-z0-9-]+', name) or name in headers
                or any(c < 32 or c == 127 for c in value)):
            raise ValueError('Ambiguous Headroom request header')
        headers[name] = value
    upgrade = headers.get(b'upgrade', b'').lower() == b'websocket'
    if (version != b'HTTP/1.1' or headers.get(b'host') != b'127.0.0.1:9787'
            or b'transfer-encoding' in headers
            or (method, target) not in {
                (b'POST', b'/v1/responses'), (b'POST', b'/v1/responses/compact'),
                (b'GET', b'/v1/models'), (b'GET', b'/v1/responses')}
            or (method == b'GET' and target == b'/v1/responses' and not upgrade)
            or (upgrade and (method, target) != (b'GET', b'/v1/responses'))):
        raise PermissionError('Only the approved Headroom model API is available')
    length = headers.get(b'content-length', b'0')
    if not re.fullmatch(rb'[0-9]{1,8}', length) or int(length) > 16 * 1024**2:
        raise ValueError('Invalid Headroom request body length')
    length = int(length)
    if upgrade:
        key = headers.get(b'sec-websocket-key', b'')
        try:
            valid_key = len(base64.b64decode(key, validate=True)) == 16
        except ValueError:
            valid_key = False
        if length or remainder or not valid_key or headers.get(b'connection', b'').lower() != b'upgrade':
            raise ValueError('Invalid Headroom WebSocket handshake')
    else:
        if len(remainder) > length:
            raise ValueError('Pipelined Headroom requests are forbidden')
        client.settimeout(30)
        while len(remainder) < length:
            block = client.recv(min(65536, length - len(remainder)))
            if not block:
                raise ValueError('Truncated Headroom request body')
            remainder += block
        # A single HTTP request per connection prevents a permitted model
        # request from tunnelling a second request to a control-plane API.
        headers[b'connection'] = b'close'
    rebuilt = lines[0] + b'\r\n' + b'\r\n'.join(name + b': ' + value for name, value in headers.items())
    return rebuilt + b'\r\n\r\n' + remainder, upgrade


def _headroom_upgrade_response(upstream, request):
    """Grant duplex transport only after the fixed service upgrades to WS."""
    upstream.settimeout(10)
    data = b''
    while b'\r\n\r\n' not in data:
        block = upstream.recv(min(4096, MAX_HEADER_BYTES + 1 - len(data)))
        if not block or len(data) >= MAX_HEADER_BYTES:
            raise ValueError('Invalid Headroom upgrade response')
        data += block
    head = data.split(b'\r\n\r\n', 1)[0]
    lines = head.split(b'\r\n')
    headers = {}
    for line in lines[1:]:
        name, value = line.split(b':', 1)
        name = name.lower()
        if name in headers:
            raise ValueError('Ambiguous Headroom upgrade response')
        headers[name] = value.strip()
    request_headers = dict(line.split(b': ', 1) for line in request.split(b'\r\n')[1:-2])
    key = request_headers[b'sec-websocket-key']
    accept = base64.b64encode(hashlib.sha1(key + b'258EAFA5-E914-47DA-95CA-C5AB0DC85B11').digest())
    status = lines[0].split(b' ', 2)
    upgraded = (status[:2] == [b'HTTP/1.1', b'101']
                and headers.get(b'upgrade', b'').lower() == b'websocket'
                and headers.get(b'connection', b'').lower() == b'upgrade'
                and headers.get(b'sec-websocket-accept') == accept)
    if len(status) >= 2 and status[1] == b'101' and not upgraded:
        raise ValueError('Invalid Headroom WebSocket upgrade')
    return data, upgraded


def _headroom_response(client, upstream, stop, observer=None):
    """Drain a response after client write EOF; additional requests fail closed."""
    client.settimeout(5)
    upstream.settimeout(5)
    with selectors.DefaultSelector() as selector:
        selector.register(upstream, selectors.EVENT_READ)
        selector.register(client, selectors.EVENT_READ)
        started = last_activity = time.monotonic()
        while not stop.is_set():
            now = time.monotonic()
            if now - last_activity >= IDLE_TIMEOUT or now - started >= RELAY_TIMEOUT:
                return
            for key, _ in selector.select(timeout=0.5):
                if key.fileobj is client:
                    if client.recv(1):
                        return  # Never forward a second downstream request.
                    selector.unregister(client)  # Write-half-close is not cancellation.
                    continue
                data = upstream.recv(65536)
                if not data:
                    if observer is not None:
                        observer.finish()
                    return
                if observer is not None:
                    observer.feed(data)
                client.sendall(data)
                last_activity = time.monotonic()


class HeadroomEgress(PublicEgress):
    """Fixed service and model endpoints; no general loopback or admin access."""

    def __init__(self, socket_path, *, enforce_provider_tools=False, model_evidence=None):
        super().__init__(socket_path)
        self._enforce_provider_tools = enforce_provider_tools
        self._model_evidence = model_evidence

    def _handle(self, client: socket.socket) -> None:
        upstream = None
        try:
            request, websocket = _headroom_request(client)
            if self._enforce_provider_tools:
                if websocket:
                    raise PermissionError("Opaque Headroom upgrades are not admitted")
                from agentporter.agents.provider_egress import validate_payload
                header, body = request.split(b"\r\n\r\n", 1)
                validate_payload(header, body, "api.openai.com")
            upstream = socket.create_connection(("127.0.0.1", 9787), timeout=10)
            with self._lock:
                if self._stop.is_set():
                    return
                self._connections.add(upstream)
            upstream.sendall(request)
            if websocket:
                response, upgraded = _headroom_upgrade_response(upstream, request)
                client.sendall(response)
                if upgraded:
                    _relay(client, upstream, self._stop)
                else:
                    _headroom_response(client, upstream, self._stop)
            else:
                observer = (self._model_evidence.response()
                    if self._model_evidence is not None
                    and request.split(b'\r\n', 1)[0].split(b' ')[:2] == [b'POST', b'/v1/responses']
                    else None)
                _headroom_response(client, upstream, self._stop, observer)
        except (OSError, ValueError, PermissionError):
            pass
        finally:
            with self._lock:
                self._connections.discard(client)
                self._connections.discard(upstream)
                self._threads.discard(threading.current_thread())
            client.close()
            if upstream is not None:
                upstream.close()
            self._slots.release()


def bridge(socket_path: str, port: int, command: list[str], *, set_proxy: bool = True) -> None:
    """Expose the mounted Unix endpoint inside this network namespace, then exec."""
    if not command or not os.path.isabs(command[0]):
        raise ValueError("Bridge requires an absolute worker executable")
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", port))
    listener.listen(MAX_CONNECTIONS)
    actual_port = listener.getsockname()[1]
    parent = os.getpid()
    child = os.fork()
    if child == 0:
        # Kill the relay if its direct worker parent dies, including outside a
        # PID namespace. The runtime also creates a private PID namespace.
        libc = ctypes.CDLL(None, use_errno=True)
        if libc.prctl(1, signal.SIGKILL, 0, 0, 0) != 0 or os.getppid() != parent:
            os._exit(1)
        null = os.open(os.devnull, os.O_RDWR)
        for fd in (0, 1, 2):
            os.dup2(null, fd)
        if null > 2:
            os.close(null)
        slots = threading.BoundedSemaphore(MAX_CONNECTIONS)
        def handle(client: socket.socket) -> None:
            try:
                _bridge_connection(client, socket_path)
            finally:
                slots.release()
        try:
            while True:
                client, _ = listener.accept()
                if not slots.acquire(blocking=False):
                    client.close()
                    continue
                threading.Thread(target=handle, args=(client,), daemon=True).start()
        finally:
            os._exit(0)
    listener.close()
    env = dict(os.environ)
    if set_proxy:
        for key in tuple(env):
            if key.lower() in {"http_proxy", "https_proxy", "all_proxy", "no_proxy"}:
                del env[key]
        proxy = f"http://127.0.0.1:{actual_port}"
        env.update({"HTTPS_PROXY": proxy, "https_proxy": proxy, "HTTP_PROXY": proxy, "http_proxy": proxy})
    # These addresses belong only to the worker's isolated network namespace.
    # Local CLI RPC (for example OpenCode's standalone server) must not be sent
    # to the public CONNECT endpoint. Host loopback remains unreachable.
    loopback = "127.0.0.1,localhost,::1"
    env.update({"NO_PROXY": loopback, "no_proxy": loopback})
    try:
        os.execvpe(command[0], command, env)
    finally:
        with contextlib.suppress(ProcessLookupError):
            os.kill(child, signal.SIGKILL)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=["bridge", "headroom-bridge"])
    parser.add_argument("--socket", required=True)
    parser.add_argument("--port", type=int, default=18765)
    args, command = parser.parse_known_args()
    if command[:1] == ["--"]:
        command = command[1:]
    if args.mode == "headroom-bridge" and args.port != 9787:
        parser.error("Headroom bridge is fixed to port 9787")
    bridge(args.socket, args.port, command, set_proxy=args.mode == "bridge")


if __name__ == "__main__":
    main()
