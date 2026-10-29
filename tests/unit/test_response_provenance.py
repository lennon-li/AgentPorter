import importlib.util
import json
from pathlib import Path
import pytest

import agentporter.provenance as p


def response(model='reported-model', status='completed'):
    return {'type':'response.completed', 'response':{'status':status,'model':model}}


def stream(*events):
    return b''.join(b'data: '+json.dumps(e).encode()+b'\n\n' for e in events)


def http(body, content_type=b'text/event-stream', *, chunked=False):
    head=b'HTTP/1.1 200 OK\r\nContent-Type: '+content_type+b'\r\n'
    if chunked:
        wire=b''.join(f'{len(body[i:i+7]):x}\r\n'.encode()+body[i:i+7]+b'\r\n' for i in range(0,len(body),7))+b'0\r\n\r\n'
        return head+b'Transfer-Encoding: chunked\r\n\r\n'+wire
    return head+b'Content-Length: '+str(len(body)).encode()+b'\r\n\r\n'+body


def observed(wire, stride=1):
    evidence=p.ProviderModelEvidence(); observer=evidence.response()
    for i in range(0,len(wire),stride): observer.feed(wire[i:i+stride])
    observer.finish()
    return evidence


@pytest.mark.parametrize('chunked',[False,True])
@pytest.mark.parametrize('stride',[1,2,17,65536])
def test_complete_provider_sse_reports_model(chunked,stride):
    e=observed(http(stream(response()),chunked=chunked),stride)
    assert p.extract_actual_model('ignored','ignored',evidence=e)=='reported-model'


def test_nonstream_json():
    body=json.dumps(response()['response']).encode()
    assert observed(http(body,b'application/json'),17).actual_model()=='reported-model'


@pytest.mark.parametrize('event',[
    {'type':'response.output_text.delta','delta':'{"model":"spoof"}'},
    {'type':'response.created','response':{'status':'completed','model':'spoof'}},
    response(status='failed'),response(status='in_progress'),
    {'type':'response.completed','response':{'status':'completed'}},
    {'type':'response.completed','response':{'status':'completed','model':'bad\nmodel'}},
])
def test_untrusted_or_incomplete_content_never_reports_model(event):
    assert observed(http(stream(event))).actual_model()=='unknown'


@pytest.mark.parametrize('wire',[
    b'HTTP/1.1 403 Forbidden\r\nContent-Type: text/event-stream\r\n\r\n'+stream(response()),
    b'HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Encoding: gzip\r\n\r\n'+stream(response()),
    b'HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\nContent-Length: 2\r\n\r\n',
    b'HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Type: text/event-stream\r\n\r\n'+stream(response()),
    http(b'data: {"type":"response.completed","response":{"status":"completed","model":"a","model":"b"}}\n\n'),
    http(stream(response()),chunked=True)[:-1],
    http(stream(response()))[:-2],
])
def test_malformed_ambiguous_and_error_responses_are_unknown(wire):
    assert observed(wire,17).actual_model()=='unknown'


def test_multiple_models_are_ambiguous_and_launches_are_separate():
    a=p.ProviderModelEvidence(); b=p.ProviderModelEvidence()
    o=a.response();o.feed(http(stream(response('a'))));o.finish()
    assert a.actual_model()=='a' and b.actual_model()=='unknown'
    o=a.response();o.feed(http(stream(response('b'))));o.finish()
    assert a.actual_model()=='unknown'


def test_incomplete_second_chunk_is_unknown():
    raw=http(stream(response()),chunked=True)
    assert observed(raw[:-5]).actual_model()=='unknown'


def test_log_paths_and_arbitrary_objects_never_supply_model(tmp_path):
    f=tmp_path/'stdout';f.write_text(json.dumps(response()))
    assert p.extract_actual_model(str(f),str(f))=='unknown'
    class Forged:
        def actual_model(self): return 'forged'
    assert p.extract_actual_model(str(f),str(f),evidence=Forged())=='unknown'


def test_oversized_event_is_discarded_and_buffer_cleared():
    o=p.ProviderModelEvidence().response()
    o.feed(b'HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n\r\n')
    o.feed(b'data: '+b'x'*262145)
    assert o._disabled and not o._body and not o._data


def test_worker_text_is_not_accepted_as_plain_json_model():
    assert observed(http(json.dumps({'model':'spoof','status':'completed'}).encode())).actual_model()=='unknown'


@pytest.mark.parametrize('chunked',[False,True])
@pytest.mark.parametrize('suffix',[b'EXCESS',b'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}'])
def test_extra_bytes_after_message_boundary_reject_regardless_of_transport_split(chunked,suffix):
    raw=http(stream(response()),chunked=chunked)
    for blocks in ([raw+suffix],[raw,suffix],[raw,suffix[:1],suffix[1:]]):
        evidence=p.ProviderModelEvidence();observer=evidence.response()
        for block in blocks:observer.feed(block)
        observer.finish()
        assert evidence.actual_model()=='unknown'


@pytest.mark.parametrize('chunked',[False,True])
def test_boundary_does_not_commit_before_upstream_finish(chunked):
    evidence=p.ProviderModelEvidence();observer=evidence.response()
    observer.feed(http(stream(response()),chunked=chunked))
    assert evidence.actual_model()=='unknown'
    observer.finish()
    assert evidence.actual_model()=='reported-model'
    # Caller misuse after EOF cannot preserve a contradicted metadata claim.
    observer.feed(b'EXCESS')
    assert evidence.actual_model()=='unknown'
