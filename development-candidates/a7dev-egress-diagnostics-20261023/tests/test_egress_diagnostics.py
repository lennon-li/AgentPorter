"""Offline synthetic journal redaction and relay-preservation checks."""
from pathlib import Path
import hashlib
import importlib.util
import json
import logging
import sys
import threading
import pytest

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,'/opt/agentporter-development/current/src')
import agentporter.agents
spec=importlib.util.spec_from_file_location('agentporter.agents.provider_egress',ROOT/'src/agentporter/agents/provider_egress.py')
broker=importlib.util.module_from_spec(spec);sys.modules[spec.name]=broker;spec.loader.exec_module(broker)
agentporter.agents.provider_egress=broker


def make_relay(agent='argie'):
    obj=broker.ProviderEgress.__new__(broker.ProviderEgress)
    obj.rules=broker.provider_rules(agent)
    obj._diagnostic_agent=agent;obj._diagnostic_count=0;obj._diagnostic_lock=threading.Lock()
    obj._lock=threading.Lock();obj._connections=set();obj._threads=set();obj._slots=threading.Semaphore(0)
    obj._stop=threading.Event();obj._model_evidence=None
    return obj


def events(caplog):
    return [json.loads(r.getMessage().partition('provider_egress_diagnostic ')[2]) for r in caplog.records if r.name==broker._DIAGNOSTIC_LOGGER.name]


def test_fixed_allowlists_and_network_policy_unchanged():
    m=json.loads((ROOT/'manifest.json').read_text());raw=Path(m['source']).read_bytes()
    assert hashlib.sha256(raw).hexdigest()==m['source_sha256']
    s=importlib.util.spec_from_file_location('diagnostic_baseline_provider',m['source'])
    baseline=importlib.util.module_from_spec(s);s.loader.exec_module(baseline)
    assert baseline.RULES==broker.RULES
    assert baseline.MAX_HEADER==broker.MAX_HEADER and baseline.MAX_BODY==broker.MAX_BODY
    for agent in broker.RULES:
        assert baseline.provider_rules(agent,True)==broker.provider_rules(agent,True)


def test_malicious_metadata_never_enters_journal(caplog):
    caplog.set_level(logging.WARNING)
    relay=make_relay();relay._diagnostic_agent='SECRET_ACCOUNT\n'
    relay._diagnostic(stage='SECRET_STAGE',host='SECRET_HOST/?token=SECRET',method='SECRET_METHOD',operation='SECRET_OPERATION',status='SECRET_STATUS')
    row=events(caplog)[0]
    assert set(row)=={'event','agent','host','method','operation','stage','error_code','upstream_status'}
    assert row['agent']==row['host']==row['method']==row['operation']==row['stage']=='unknown'
    assert row['upstream_status'] is None and 'SECRET' not in caplog.text


@pytest.mark.parametrize('value',[None,False,99,600,'403',float('nan')])
def test_status_is_bounded_integer(caplog,value):
    make_relay()._diagnostic(stage='upstream_status',status=value)
    assert events(caplog)[0]['upstream_status'] is None


def test_event_cap_is_per_launch_and_thread_safe(caplog):
    relay=make_relay()
    threads=[threading.Thread(target=lambda:[relay._diagnostic(stage='connect') for _ in range(10)]) for _ in range(10)]
    for t in threads:t.start()
    for t in threads:t.join()
    assert len(events(caplog))==32 and relay._diagnostic_count==32
    other=make_relay();other._diagnostic(stage='connect')
    assert len(events(caplog))==33


@pytest.mark.parametrize('header,expected',[
    (b'POST /v1internal:streamGenerateContent?token=SECRET_QUERY HTTP/1.1\r\nAuthorization: SECRET_HEADER',('POST','google_stream_generate')),
    (b'GET /SECRET_PATH HTTP/1.1',('GET','unknown')),
    (b'SECRET_METHOD /SECRET_PATH HTTP/1.1',('unknown','unknown')),
    (b'\xff /SECRET_PATH HTTP/1.1',('unknown','unknown')),
])
def test_header_parser_returns_enums_only(header,expected):
    assert broker._diagnostic_operation(header)==expected


class Conn:
    def __init__(self):self.sent=[];self.closed=False
    def sendall(self,data):self.sent.append(data)
    def recv(self,n):return b''
    def settimeout(self,value):pass
    def close(self):self.closed=True


class TLS:
    def __init__(self,conn):self.conn=conn;self.names=[]
    def wrap_socket(self,raw,**kwargs):self.names.append(kwargs);return self.conn


def setup_flow(monkeypatch,*,status=403,agent='argie',host='daily-cloudcode-pa.googleapis.com'):
    relay=make_relay(agent);client=Conn();upstream=Conn();raw=Conn()
    relay._contexts={host:TLS(client)};relay._upstream_context=TLS(upstream)
    monkeypatch.setattr(broker,'_read_connect',lambda c:(host,b''))
    monkeypatch.setattr(broker,'_connect_public',lambda h:raw)
    request=b'POST /v1internal:streamGenerateContent?token=SECRET_QUERY HTTP/1.1\r\nHost: daily-cloudcode-pa.googleapis.com\r\nAuthorization: Bearer SECRET_AUTH\r\nContent-Length: 2'
    response=f'HTTP/1.1 {status} SECRET_REASON\r\nContent-Length: 11\r\nX-SECRET-HEADER: SECRET_RESPONSE_HEADER'.encode()
    monkeypatch.setattr(broker,'read_header',lambda c,**kw:(request,b'{}') if c is client else (response,b'SECRET_BODY'))
    return relay,client,upstream,raw,request,response


def test_upstream_403_is_classified_and_original_bytes_forwarded(caplog,monkeypatch):
    relay,client,upstream,raw,request,response=setup_flow(monkeypatch)
    relay._handle(client)
    row=events(caplog)[0]
    assert row=={'event':'provider_egress_diagnostic','agent':'argie','host':'daily-cloudcode-pa.googleapis.com',
        'method':'POST','operation':'google_stream_generate','stage':'upstream_status','error_code':'upstream_non_2xx','upstream_status':403}
    assert client.sent[-1]==response+b'\r\n\r\nSECRET_BODY'
    assert upstream.sent[0].endswith(b'\r\n\r\n{}')
    assert relay._upstream_context.names==[{'server_hostname':'daily-cloudcode-pa.googleapis.com'}]
    assert 'SECRET' not in caplog.text


def test_success_does_not_emit_diagnostic(caplog,monkeypatch):
    relay,client,upstream,raw,request,response=setup_flow(monkeypatch,status=200)
    relay._handle(client)
    assert not events(caplog) and client.sent[-1]==response+b'\r\n\r\nSECRET_BODY'


def test_log_failure_never_changes_upstream_response(monkeypatch):
    relay,client,upstream,raw,request,response=setup_flow(monkeypatch)
    monkeypatch.setattr(broker._DIAGNOSTIC_LOGGER,'warning',lambda *a,**kw:(_ for _ in ()).throw(ValueError('SECRET_LOGGER_ERROR')))
    relay._handle(client)
    assert client.sent[-1]==response+b'\r\n\r\nSECRET_BODY'


@pytest.mark.parametrize('stage',['payload','upstream_connect','upstream_tls'])
def test_local_failure_has_fixed_stage_and_no_exception_text(caplog,monkeypatch,stage):
    relay,client,upstream,raw,request,response=setup_flow(monkeypatch)
    def fail(*a,**kw):raise ValueError('SECRET_EXCEPTION_TEXT token=SECRET')
    if stage=='payload':monkeypatch.setattr(broker,'validate_payload',fail)
    elif stage=='upstream_connect':monkeypatch.setattr(broker,'_connect_public',fail)
    else:monkeypatch.setattr(relay._upstream_context,'wrap_socket',fail)
    relay._handle(client)
    row=events(caplog)[0]
    assert row['stage']==stage and row['error_code']=='local_rejection_or_transport_failure'
    assert row['upstream_status'] is None and 'SECRET' not in caplog.text
    assert client.sent[-1].startswith(b'HTTP/1.1 403')


def test_malicious_connect_host_is_unknown_not_logged(caplog,monkeypatch):
    relay=make_relay();client=Conn()
    monkeypatch.setattr(broker,'_read_connect',lambda c:('SECRET_HOST.invalid',b''))
    relay._handle(client)
    assert events(caplog)[0]['host']=='unknown' and events(caplog)[0]['stage']=='connect'
    assert 'SECRET' not in caplog.text


@pytest.mark.parametrize('host',[
    'daily-cloudcode-pa.sandbox.googleapis.com',
    'autopush-cloudcode-pa.sandbox.googleapis.com',
])
def test_recognized_native_denied_origins_are_diagnostic_only(caplog,host):
    relay=make_relay()
    assert host not in relay.rules
    assert not broker.operation_allowed(relay.rules,host,'POST','/v1internal:streamGenerateContent')
    relay._diagnostic(stage='connect',host=host)
    assert events(caplog)[0]['host']==host
    relay._diagnostic(stage='connect',host=host+'.SECRET_EVIL')
    assert events(caplog)[-1]['host']=='unknown' and 'SECRET' not in caplog.text


@pytest.mark.parametrize('agent,method,path,label',[
    ('argie','POST','/v1internal:getCodeAssistGlobalUserSetting','google_global_user_setting'),
    ('argie','POST','/v1internal:listCloudAICompanionProjects','google_companion_projects'),
    ('argie','POST','/v1internal:initiateMeshSession','google_mesh_session'),
    ('argie','POST','/v1internal:internalAtomicAgenticChat','google_atomic_agentic_chat'),
    ('argie','POST','/v1internal:fetchCodeCustomizationState','google_code_customization'),
    ('argie','POST','/v1internal:listAuthorizedDevices','google_authorized_devices'),
    ('phil','GET','/copilot_internal/v2/token','copilot_token_exchange'),
])
def test_recognized_native_denied_operations_are_diagnostic_only(caplog,agent,method,path,label):
    relay=make_relay(agent)
    host='api.github.com' if agent=='phil' else 'daily-cloudcode-pa.googleapis.com'
    assert not broker.operation_allowed(relay.rules,host,method,path)
    parsed_method,operation=broker._diagnostic_operation(f'{method} {path}?token=SECRET_QUERY HTTP/1.1'.encode())
    assert (parsed_method,operation)==(method,label)
    relay._diagnostic(stage='request_header',host=host,method=parsed_method,operation=operation)
    assert events(caplog)[0]['operation']==label and 'SECRET' not in caplog.text
