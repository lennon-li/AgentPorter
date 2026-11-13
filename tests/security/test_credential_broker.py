"""Real owner/worker socket protocol with synthetic account credentials only."""
from contextlib import contextmanager
import json
import os
from pathlib import Path
import socket
import tempfile
import threading
import base64
import time
import hashlib
import struct

import pytest

from agentporter.agents.credential_broker import (
    BrokerCredentialLease, CredentialBroker, _receive, _send, load_policy, native_run,
)
from tests.security.test_credential_lease import auth
from tests.security.test_development_runtime import runtime_factory, no_probe, save


@pytest.fixture
def broker(tmp_path):
    source = tmp_path/'native-account'
    source.mkdir(mode=0o700)
    source = source/'auth.json'
    source.write_bytes(auth())
    source.chmod(0o600)
    state = tmp_path/'broker-state'
    state.mkdir(mode=0o700)
    # Production policy requires distinct UIDs. This fixture shares the test
    # user's UID so no real account, privileged installation or login is used;
    # actual SO_PEERCRED validation is still performed on both ends.
    with tempfile.TemporaryDirectory(prefix='bcc-auth-') as short:
        path = Path(short)/'auth.sock'
        policy = {'owner_uid': os.getuid(), 'worker_uid': os.getuid(),
                  'socket_path': str(path), 'state_dir': str(state),
                  'accounts': {'prof': {'auth_file': str(source), 'account_id': 'research',
                      'native_executable': str(Path('/usr/bin/python3').resolve())}}}
        server = CredentialBroker(policy)
        stopped = threading.Event()
        children = []
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
            listener.bind(str(path))
            path.chmod(0o600)
            listener.listen(8)
            listener.settimeout(.1)
            def serve():
                while not stopped.is_set():
                    try:
                        connection, _ = listener.accept()
                    except socket.timeout:
                        continue
                    def handle(channel):
                        with channel:
                            server.handle(channel)
                    child = threading.Thread(target=handle, args=(connection,), daemon=True)
                    children.append(child)
                    child.start()
            thread = threading.Thread(target=serve)
            thread.start()
            try:
                yield source, policy, server
            finally:
                stopped.set()
                thread.join(2)
                for child in children:
                    child.join(2)
                assert not thread.is_alive()
                assert all(not child.is_alive() for child in children)


def client_config(policy, account='prof'):
    return {'owner_uid': policy['owner_uid'], 'socket_path': policy['socket_path'], 'account': account}


def provider_account(broker,tmp_path,provider):
    source,policy,server=broker
    policy['mode']='access_only'
    name='.credentials.json' if provider=='claude' else 'config.json'
    target=source.with_name(name)
    account={'provider':provider,'auth_file':str(target),'account_id':'intended-owner'}
    if provider=='claude':
        identity=source.with_name('identity.json')
        identity.write_text(json.dumps({'oauthAccount':{'accountUuid':'intended-owner'}}));identity.chmod(0o600)
        account['identity_file']=str(identity)
        data={'claudeAiOauth':{'accessToken':'synthetic-access','refreshToken':'never-delegate-refresh',
              'expiresAt':(time.time()+3600)*1000,'scopes':['user:inference'],'subscriptionType':'max'}}
    else:
        data={'authTokens':{'github.com':'synthetic-native-token'},'copilotTokens':{},
              'lastLoggedInUser':{'login':'intended-owner','host':'github.com'},
              'mcpServers':{'hostile':'must not enter worker'},'trustedFolders':['/host/private']}
    target.write_text(json.dumps(data));target.chmod(0o600)
    policy['accounts']['prof']=account
    server.account_locks={str(target):threading.Lock()}
    config={**client_config(policy),'provider':provider}
    return target,policy,config,data


@pytest.mark.parametrize('provider',['claude','copilot'])
def test_provider_uses_fresh_native_auth_without_worker_writeback(broker,tmp_path,provider):
    source,policy,config,data=provider_account(broker,tmp_path,provider)
    before=source.read_bytes()
    target=tmp_path/'provider-worker/auth.json'
    lease=BrokerCredentialLease(config,target)
    issued=json.loads(target.read_bytes())
    assert 'never-delegate-refresh' not in target.read_text()
    assert 'mcpServers' not in issued and 'trustedFolders' not in issued
    target.write_text('{"hostile":"never write this back"}')
    lease.finish()
    assert source.read_bytes()==before
    target.unlink()
    if provider=='claude':data['claudeAiOauth']['accessToken']='new-native-access'
    else:data['authTokens']['github.com']='new-native-access'
    source.write_text(json.dumps(data))
    lease=BrokerCredentialLease(config,target)
    assert 'new-native-access' in target.read_text()
    lease.finish()


@pytest.mark.parametrize('provider',['claude','copilot'])
def test_provider_account_switch_denied(broker,tmp_path,provider):
    source,policy,config,data=provider_account(broker,tmp_path,provider)
    if provider=='claude':
        Path(policy['accounts']['prof']['identity_file']).write_text(json.dumps({'oauthAccount':{'accountUuid':'other-owner'}}))
    else:
        data['lastLoggedInUser']['login']='other-owner';source.write_text(json.dumps(data))
    with pytest.raises(PermissionError,match='no copied-token fallback'):
        BrokerCredentialLease(config,tmp_path/'worker/auth.json')


def test_expired_claude_access_does_not_delegate_refresh(broker,tmp_path):
    source,_,config,data=provider_account(broker,tmp_path,'claude')
    data['claudeAiOauth']['expiresAt']=(time.time()+100)*1000
    source.write_text(json.dumps(data))
    with pytest.raises(PermissionError,match='no copied-token fallback'):
        BrokerCredentialLease(config,tmp_path/'worker/auth.json')


@pytest.mark.parametrize('agent,provider,destination',[
    ('claude_agent','claude','.claude/.credentials.json'),
    ('copilot_agent','copilot','.copilot-agent/config.json')])
def test_runtime_native_provider_custody(broker,tmp_path,runtime_factory,monkeypatch,agent,provider,destination):
    source,policy,client,_=provider_account(broker,tmp_path,provider)
    runtime,config,path,workspace,_=runtime_factory()
    config['workers'][agent]['credentials']={}
    config['workers'][agent]['credential_broker']=client
    save(config,path);no_probe(monkeypatch,runtime)
    launch=runtime.prepare(agent,str(workspace),False,['/usr/bin/python3','--version'])
    home=Path(launch.command[launch.command.index('/home/worker')-1])
    assert (home/destination).is_file()
    assert policy['socket_path'] not in launch.command
    launch.cleanup()
    assert not home.exists()


def test_native_and_worker_use_one_authoritative_account(broker, tmp_path, capsys):
    source, policy, _ = broker
    target = tmp_path/'worker/auth.json'
    lease = BrokerCredentialLease(client_config(policy), target)
    target.write_bytes(auth('worker-rotated'))
    lease.finish()
    assert source.read_bytes() == auth('worker-rotated')
    code = ("import os,pathlib; p=pathlib.Path(os.environ['CODEX_HOME'])/'auth.json'; "
            "assert p.read_bytes()=="+repr(auth('worker-rotated'))+"; p.write_bytes("+repr(auth('native-rotated'))+")")
    assert native_run(policy, 'prof', ['-c', code]) == 0
    assert source.read_bytes() == auth('native-rotated')
    target.unlink()
    lease = BrokerCredentialLease(client_config(policy), target)
    assert target.read_bytes() == auth('native-rotated')
    lease.finish()
    assert {p.name for p in Path(policy['state_dir']).iterdir()} == {'events.jsonl'}
    audit = (Path(policy['state_dir'])/'events.jsonl').read_text()
    assert 'rotated' not in audit and 'research' not in audit
    assert not list(source.parent.glob('*pending*'))
    assert 'rotated' not in capsys.readouterr().out


def test_account_aliases_serialize_native_and_worker_launches(broker, tmp_path):
    source, policy, _ = broker
    policy['accounts']['prof-peer'] = dict(policy['accounts']['prof'])
    first = BrokerCredentialLease(client_config(policy), tmp_path/'first/auth.json')
    try:
        with pytest.raises(PermissionError, match='no copied-token fallback'):
            BrokerCredentialLease(client_config(policy, 'prof-peer'), tmp_path/'second/auth.json')
        with pytest.raises(PermissionError, match='active worker'):
            native_run(policy, 'prof', ['-c', "raise AssertionError('must not execute')"])
    finally:
        first.finish()
    assert source.read_bytes() == auth()


def test_caller_paths_and_unknown_accounts_never_select_an_auth_file(broker, tmp_path):
    source, policy, _ = broker
    for request in (
        {'version': 1, 'op': 'begin', 'account': 'prof', 'auth_file': '/host/private'},
        {'version': 1, 'op': 'begin', 'account': 'another-account'},
    ):
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as channel:
            channel.settimeout(5)
            channel.connect(policy['socket_path'])
            _send(channel, request)
            assert _receive(channel)['status'] == 'denied'
    assert source.read_bytes() == auth()
    assert not list(source.parent.glob('*pending*'))


def test_worker_account_switch_retains_recovery_without_changing_canonical_auth(broker, tmp_path):
    source, policy, _ = broker
    target = tmp_path/'worker/auth.json'
    lease = BrokerCredentialLease(client_config(policy), target)
    target.write_bytes(auth('switched', account='personal'))
    with pytest.raises(PermissionError, match='owner recovery'):
        lease.finish()
    assert source.read_bytes() == auth()
    assert target.read_bytes() == auth('switched', account='personal')
    assert list(source.parent.glob('*pending*'))


def test_unenrolled_external_rotation_cannot_be_blindly_overwritten(broker, tmp_path):
    source, policy, _ = broker
    target = tmp_path/'worker/auth.json'
    lease = BrokerCredentialLease(client_config(policy), target)
    target.write_bytes(auth('worker'))
    source.write_bytes(auth('external'))
    with pytest.raises(PermissionError, match='owner recovery'):
        lease.finish()
    assert source.read_bytes() == auth('external')
    assert target.read_bytes() == auth('worker')


def test_wrong_worker_uid_cannot_obtain_authentication(broker, tmp_path):
    source, policy, server = broker
    policy['worker_uid'] += 1
    with pytest.raises(PermissionError, match='no copied-token fallback'):
        BrokerCredentialLease(client_config(policy), tmp_path/'worker/auth.json')
    assert not list(source.parent.glob('*pending*'))


def test_wrong_broker_uid_cannot_be_substituted(broker, tmp_path):
    _, policy, _ = broker
    config = dict(client_config(policy), owner_uid=os.getuid()+1)
    with pytest.raises(PermissionError, match='Untrusted'):
        BrokerCredentialLease(config, tmp_path/'worker/auth.json')


def test_runtime_broker_mode_replaces_worker_auth_snapshots(broker, runtime_factory, monkeypatch):
    source, policy, _ = broker
    runtime, config, path, workspace, _ = runtime_factory()
    profile = path.parent/'config.toml'
    profile.write_text('model = "gpt-6.1-sol"\n')
    profile.chmod(0o600)
    spec = config['workers']['codex_impl']
    spec['credentials'] = {'.codex/config.toml': str(profile)}
    spec['credential_broker'] = client_config(policy)
    save(config, path)
    no_probe(monkeypatch, runtime)
    launch = runtime.prepare('codex_impl', str(workspace), False, ['/usr/bin/python3', '--version'])
    home = Path(launch.command[launch.command.index('/home/worker')-1])
    assert (home/'.codex/auth.json').read_bytes() == auth()
    assert policy['socket_path'] not in launch.command
    (home/'.codex/auth.json').write_bytes(auth('runtime'))
    launch.cleanup()
    assert source.read_bytes() == auth('runtime')
    assert not home.exists()


def test_untrusted_operator_policy_cannot_enable_broker(tmp_path):
    path = tmp_path/'policy.json'
    path.write_text('{}')
    with pytest.raises(PermissionError):
        load_policy(path)


def access_auth(*, ttl=3600, account='research'):
    payload = base64.urlsafe_b64encode(json.dumps({'exp': time.time()+ttl}).encode()).decode().rstrip('=')
    return json.dumps({'auth_mode': 'chatgpt', 'tokens': {'access_token': 'header.'+payload+'.signature',
        'id_token': 'synthetic-identity', 'refresh_token': 'native-renewal-secret', 'account_id': account}}).encode()


def native_websocket(channel, reader):
    assert reader.readline() == b'GET / HTTP/1.1\r\n'
    headers = {}
    while True:
        raw = reader.readline()
        if raw == b'\r\n': break
        key, value = raw.decode().strip().split(':', 1)
        headers[key.lower()] = value.strip()
    key = headers['sec-websocket-key']
    accept = base64.b64encode(hashlib.sha1((key+'258EAFA5-E914-47DA-95CA-C5AB0DC85B11').encode(), usedforsecurity=False).digest()).decode()
    channel.sendall(('HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: '+accept+'\r\n\r\n').encode())
    def receive():
        first, second = reader.read(2)
        assert first == 0x81 and second & 128
        size = second & 127
        if size == 126: size, = struct.unpack('>H', reader.read(2))
        mask = reader.read(4)
        raw = reader.read(size)
        return json.loads(bytes(value ^ mask[i%4] for i, value in enumerate(raw)))
    def send(value):
        raw = json.dumps(value).encode()
        prefix = bytes([0x81, len(raw)]) if len(raw)<126 else b'\x81\x7e'+struct.pack('>H',len(raw))
        channel.sendall(prefix+raw)
    return receive, send


def test_access_only_never_delegates_or_writes_refresh_credentials(broker, tmp_path):
    source, policy, server = broker
    policy['mode'] = 'access_only'
    source.write_bytes(access_auth())
    original = source.read_bytes()
    first = BrokerCredentialLease(client_config(policy), tmp_path/'one/auth.json')
    second = BrokerCredentialLease(client_config(policy), tmp_path/'two/auth.json')
    for lease in (first, second):
        issued = json.loads(lease.target.read_bytes())
        assert issued['tokens']['refresh_token'] == ''
        assert b'native-renewal-secret' not in lease.target.read_bytes()
        lease.target.write_bytes(auth('hostile-worker', account='personal'))
        lease.finish()
    assert source.read_bytes() == original
    assert not list(source.parent.glob('*pending*'))
    assert not list(Path(policy['state_dir']).glob('lease-*'))
    assert (Path(policy['state_dir'])/'events.jsonl').read_text().count('access_issued') == 2
    # A service restart has no in-flight refresh state to recover.
    restarted = CredentialBroker(policy)
    assert restarted.account_locks
    third = BrokerCredentialLease(client_config(policy), tmp_path/'three/auth.json')
    third.finish()
    assert source.read_bytes() == original


@pytest.mark.parametrize('ttl', [-1, 300, 930, 960, 1200, 1259])
def test_short_access_without_native_authority_fails_closed(broker, tmp_path, ttl):
    source, policy, _ = broker
    policy['mode'] = 'access_only'
    policy['accounts']['prof']['native_socket'] = str(source.parent/'absent.sock')
    source.write_bytes(access_auth(ttl=ttl))
    original = source.read_bytes()
    with pytest.raises(PermissionError, match='no copied-token fallback'):
        BrokerCredentialLease(client_config(policy), tmp_path/'worker/auth.json')
    assert source.read_bytes() == original


def test_access_renewal_uses_existing_native_daemon_protocol(broker, tmp_path):
    source, policy, _ = broker
    policy['mode'] = 'access_only'
    source.write_bytes(access_auth(ttl=60))
    path = Path(policy['socket_path']).with_name('native.sock')
    policy['accounts']['prof']['native_socket'] = str(path)
    observed = []
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
        listener.bind(str(path))
        path.chmod(0o600)
        listener.listen(1)
        def native():
            channel, _ = listener.accept()
            with channel, channel.makefile('rb') as reader:
                receive, send = native_websocket(channel, reader)
                message = receive()
                observed.append(message['method'])
                send({'id': 1, 'result': {}})
                observed.append(receive()['method'])
                message = receive()
                observed.append(message)
                source.write_bytes(access_auth())
                send({'id': 2, 'result': {'account': {'type': 'chatgpt'}}})
        thread = threading.Thread(target=native)
        thread.start()
        lease = BrokerCredentialLease(client_config(policy), tmp_path/'worker/auth.json')
        lease.finish()
        thread.join(2)
        assert not thread.is_alive()
    assert observed == ['initialize', 'initialized', {'id': 2, 'method': 'account/read', 'params': {'refreshToken': True}}]
    assert json.loads(source.read_bytes())['tokens']['refresh_token'] == 'native-renewal-secret'
    assert json.loads(lease.target.read_bytes())['tokens']['refresh_token'] == ''


def test_changed_native_account_is_not_silently_served_to_a_worker(broker, tmp_path):
    source, policy, _ = broker
    source.write_bytes(auth(account='personal'))
    with pytest.raises(PermissionError, match='no copied-token fallback'):
        BrokerCredentialLease(client_config(policy), tmp_path/'worker/auth.json')


def test_detached_native_authentication_writer_retains_account_guard(broker, tmp_path):
    import signal
    source, policy, _ = broker
    marker = tmp_path/'owned-child-pid'
    code = ("import subprocess,sys,pathlib; p=subprocess.Popen([sys.executable,'-c',"
            "'import time; time.sleep(60)'],start_new_session=True); "
            "pathlib.Path("+repr(str(marker))+").write_text(str(p.pid))")
    try:
        with pytest.raises(PermissionError, match='descendants remain'):
            native_run(policy, 'prof', ['-c', code])
        assert list(source.parent.glob('*pending*'))
        assert source.read_bytes() == auth()
    finally:
        if marker.exists():
            pid = int(marker.read_text())
            try:
                os.kill(pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            try:
                os.waitpid(pid, 0)
            except ChildProcessError:
                pass
