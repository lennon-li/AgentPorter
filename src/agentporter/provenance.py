"""Model provenance from host-owned provider response observers, never worker logs.

The observer belongs to one prepared confined launch and has no worker-visible
file/socket/descriptor. Only the existing exact-origin relay may feed upstream
HTTP response bytes. This is provider/runtime-reported evidence, not a guarantee
about a provider's private backend. Requested/configured models are never used.
"""
from __future__ import annotations

import json
import re
import threading

_MODEL = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:/+-]{0,127}\Z")
_MAX_HEADER = 8192
_MAX_EVENT = 262144


def _object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate member")
        result[key] = value
    return result


class ProviderModelEvidence:
    """One launch's in-memory, host-only completed-response evidence."""
    def __init__(self):
        self._lock = threading.Lock()
        self._models = set()
        self._ambiguous = False

    def response(self):
        return _ResponseObserver(self)

    def _record(self, model):
        with self._lock:
            if not isinstance(model, str) or not _MODEL.fullmatch(model):
                self._ambiguous = True
            elif len(self._models) < 2:
                self._models.add(model)

    def _invalidate(self):
        with self._lock:
            self._ambiguous = True

    def actual_model(self):
        with self._lock:
            if self._ambiguous or len(self._models) != 1:
                return "unknown"
            return next(iter(self._models))


class _ResponseObserver:
    """Bounded best-effort HTTP/1 observer; never controls forwarding.

    Supports uncompressed Responses SSE and JSON, including chunked HTTP. Any
    unknown encoding, malformed framing, oversized event or incomplete response
    provides no evidence. It retains at most one bounded event, never a transcript.
    """
    def __init__(self, evidence):
        self._evidence = evidence
        self._header = bytearray()
        self._wire = bytearray()
        self._body = bytearray()
        self._data = []
        self._event_size = 0
        self._kind = None
        self._chunked = False
        self._chunk_left = None
        self._ending = False
        self._chunk_done = False
        self._length = None
        self._received = 0
        self._disabled = False
        self._done = False
        self._message_complete = False
        self._models = []

    def feed(self, block):
        if self._disabled:
            return
        if self._done:
            if block:
                self._evidence._invalidate()
            return
        if self._message_complete:
            if block:
                self._disable()
            return
        try:
            self._feed(block)
        except (ValueError, UnicodeError, TypeError, OverflowError, RecursionError):
            self._disable()

    def _disable(self):
        self._disabled = True
        self._header.clear(); self._wire.clear(); self._body.clear()
        self._data.clear(); self._models.clear()

    def _feed(self, block):
        if self._kind is None:
            self._header.extend(block)
            boundary = self._header.find(b"\r\n\r\n")
            if boundary < 0:
                if len(self._header) > _MAX_HEADER:
                    raise ValueError()
                return
            if boundary > _MAX_HEADER:
                raise ValueError()
            header = bytes(self._header[:boundary])
            rest = bytes(self._header[boundary+4:]); self._header.clear()
            lines = header.split(b"\r\n")
            status = lines[0].split(b" ")
            if len(status) < 2 or status[0] not in (b"HTTP/1.1", b"HTTP/1.0") or status[1] != b"200":
                raise ValueError()
            headers = {}
            for line in lines[1:]:
                key, value = line.split(b":", 1); key = key.lower()
                if key in headers:
                    raise ValueError()
                headers[key] = value.strip().lower()
            if headers.get(b"content-encoding", b"identity") != b"identity":
                raise ValueError()
            kind = headers.get(b"content-type", b"").split(b";", 1)[0]
            if kind == b"text/event-stream": self._kind = "sse"
            elif kind == b"application/json": self._kind = "json"
            else: raise ValueError()
            transfer = headers.get(b"transfer-encoding")
            if transfer not in (None, b"chunked") or (transfer and b"content-length" in headers):
                raise ValueError()
            self._chunked = transfer == b"chunked"
            if b"content-length" in headers:
                self._length = int(headers[b"content-length"])
                if self._length < 0: raise ValueError()
            block = rest
        if self._chunked:
            self._wire.extend(block)
            while self._wire:
                if self._ending:
                    if len(self._wire) < 2: break
                    if self._wire != b"\r\n": raise ValueError()
                    self._wire.clear(); self._chunk_done = True
                    self._message_complete = True
                    return
                if self._chunk_left is None:
                    end = self._wire.find(b"\r\n")
                    if end < 0:
                        if len(self._wire) > 128: raise ValueError()
                        break
                    if end > 128: raise ValueError()
                    token = bytes(self._wire[:end])
                    if not re.fullmatch(rb"[0-9A-Fa-f]{1,16}", token): raise ValueError()
                    self._chunk_left = int(token, 16)
                    del self._wire[:end+2]
                    if self._chunk_left == 0:
                        self._ending = True
                        continue
                amount = min(self._chunk_left, len(self._wire))
                if amount:
                    self._content(bytes(self._wire[:amount])); del self._wire[:amount]
                    self._chunk_left -= amount
                if self._chunk_left:
                    break
                if len(self._wire) < 2: break
                if self._wire[:2] != b"\r\n": raise ValueError()
                del self._wire[:2]; self._chunk_left = None
        else:
            self._received += len(block)
            if self._length is not None and self._received > self._length: raise ValueError()
            self._content(block)
            if self._length == self._received:
                self._message_complete = True

    def _content(self, block):
        self._body.extend(block)
        if self._kind == "json":
            if len(self._body) > _MAX_EVENT: raise ValueError()
            return
        while b"\n" in self._body:
            line, _, rest = self._body.partition(b"\n"); self._body = bytearray(rest)
            line = bytes(line).removesuffix(b"\r")
            if not line:
                if self._data:
                    self._event(b"\n".join(self._data))
                self._data.clear(); self._event_size = 0
            elif line.startswith(b"data:"):
                value = line[5:].removeprefix(b" ")
                self._event_size += len(value)+1
                if self._event_size > _MAX_EVENT: raise ValueError()
                self._data.append(value)
        if len(self._body) > _MAX_EVENT: raise ValueError()

    def _event(self, raw):
        if raw == b"[DONE]": return
        data = json.loads(raw, object_pairs_hook=_object,
                          parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
        if not isinstance(data, dict): raise ValueError()
        if self._kind == "sse":
            if data.get("type") != "response.completed": return
            response = data.get("response")
        else:
            response = data
        if not isinstance(response, dict) or response.get("status") != "completed": return
        model = response.get("model")
        if not isinstance(model, str) or not _MODEL.fullmatch(model): raise ValueError()
        self._models.append(model)
        if len(self._models) > 128: raise ValueError()

    def finish(self):
        if self._disabled or self._done: return
        try:
            if self._kind is None: raise ValueError()
            if self._chunked and not self._chunk_done: raise ValueError()
            if self._length is not None and self._received != self._length: raise ValueError()
            if self._kind == "json": self._event(bytes(self._body))
            elif self._body or self._data: raise ValueError()
            for model in self._models: self._evidence._record(model)
            self._done = True
            self._body.clear(); self._data.clear(); self._models.clear()
        except (ValueError, UnicodeError, TypeError, OverflowError, RecursionError):
            self._disable()


def extract_actual_model(stdout_path, stderr_path, *, evidence=None):
    """Logs remain ignored; only the job-bound trusted observer can supply evidence."""
    return evidence.actual_model() if type(evidence) is ProviderModelEvidence else "unknown"
