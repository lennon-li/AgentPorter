import io
import json
import struct
import threading
import time

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from agentporter.agents.roster import PUBLIC_AGENT_IDS
from agentporter import worker_git_rpc
from agentporter.git_approvals import GitApprovalRequest, GitApprovalVerifier, issue_git_approval
from agentporter.worker_git_rpc import WorkerGitGrant, WorkerGitRPC

JOB = 'job_' + '1' * 24
OTHER_JOB = 'job_' + '2' * 24
REF = 'refs/heads/main'
REPO = '/srv/ws/alpha'
NOW = 1_800_000_000


class Clock:
    def __init__(self):
        self.now = NOW

    def __call__(self):
        return self.now


class FakeBackend:
    """Contract fake: real request/receipt verification, no Git or network."""

    def __init__(self, tmp_path, clock):
        self.key = Ed25519PrivateKey.generate()
        ledger = tmp_path / 'ledger'
        ledger.mkdir(mode=0o700)
        self.verifier = GitApprovalVerifier(self.key.public_key(), ledger / 'claims.db')
        self.clock = clock
        self.calls = []
        self.outcome = {'status': 'pulled', 'head': 'a' * 40}
        self.error = None
        self.repository_path = REPO
        self.operation = 'pull'
        self.mutation_lease = threading.Lock()
        self.lease_free_on_entry = None

    def prepare(self, workspace_id, remote, ref, mode):
        self.calls.append(('prepare', workspace_id, remote, ref, mode))
        return self._request(workspace_id, remote, ref, mode)

    def _request(self, workspace_id, remote, ref, mode):
        return GitApprovalRequest.from_payload({
            'operation': self.operation, 'workspace_id': workspace_id,
            'repository_path': self.repository_path, 'repository_device': 1,
            'repository_inode': 2, 'expected_head': 'b' * 40, 'expected_tree': 'c' * 40,
            'branch': 'refs/heads/main',
            'parameters': {'mode': mode, 'remote_id': remote, 'remote_ref': ref}})

    def approve(self, digest_request, lifetime=60):
        return issue_git_approval(self.key, digest_request, now=int(self.clock()), lifetime_seconds=lifetime)

    def pull(self, workspace_id, remote, ref, receipt, mode):
        self.calls.append(('pull', workspace_id, remote, ref, mode))
        # The backend owns the one non-reentrant lease; the adapter must not hold it.
        self.lease_free_on_entry = self.mutation_lease.acquire(blocking=False)
        try:
            request = self._request(workspace_id, remote, ref, mode)
            self.verifier.verify_and_consume(receipt, request, now=int(self.clock()))
            if self.error:
                raise self.error
            return dict(self.outcome)
        finally:
            if self.lease_free_on_entry:
                self.mutation_lease.release()


@pytest.fixture
def env(tmp_path):
    clock = Clock()
    backend = FakeBackend(tmp_path, clock)
    live = {JOB: True, OTHER_JOB: True}
    rpc = WorkerGitRPC(backend, lambda job, agent, ws: live.get(job, False), clock=clock)
    return rpc, backend, live, clock


def grant(job=JOB, agent='copilot_agent', **changes):
    values = dict(job_id=job, agent=agent, workspace_id='alpha', repository='root',
                  repository_path=REPO, capabilities=frozenset({'read', 'write'}),
                  allowed=frozenset({('origin', REF, 'ff-only'), ('origin', REF, 'merge'),
                                     ('origin', REF, 'rebase')}),
                  expires_at=NOW + 3600)
    values.update(changes)
    return WorkerGitGrant(**values)


def base(op='prepare', job=JOB, agent='copilot_agent', mode='ff-only', **extra):
    value = {'version': 1, 'op': op, 'job_id': job, 'agent': agent, 'workspace_id': 'alpha',
             'repository': 'root', 'remote': 'origin', 'ref': REF, 'mode': mode}
    value.update(extra)
    return value


def test_wait_returns_exact_owner_dispatched_outcome(env):
    rpc,backend,_,_=env
    rpc.issue_grant(grant())
    channel=rpc.channel(JOB)
    prepared,receipt=prepare_and_receipt(channel,backend)
    started=threading.Event();done=[]
    def waiting():
        started.set()
        done.append(channel.handle(json.dumps(base('wait',request_sha256=prepared['request_sha256']))))
    worker=threading.Thread(target=waiting);worker.start()
    assert started.wait(2)
    response=channel.handle(pull_request(prepared,receipt))
    worker.join(2)
    assert not worker.is_alive() and done==[response]


def test_wait_cannot_observe_another_job_or_unprepared_digest(env):
    rpc,backend,_,_=env
    rpc.issue_grant(grant());rpc.issue_grant(grant(job=OTHER_JOB))
    prepared,_=prepare_and_receipt(rpc.channel(JOB),backend)
    response=rpc.channel(OTHER_JOB).handle(json.dumps(base('wait',job=OTHER_JOB,
        request_sha256=prepared['request_sha256'])))
    assert response['code']=='not_prepared'
    assert rpc.channel(JOB).handle(json.dumps(base('wait',request_sha256='f'*64)))['code']=='not_prepared'


def test_revocation_wakes_waiting_worker(env):
    rpc,backend,_,_=env
    rpc.issue_grant(grant());channel=rpc.channel(JOB)
    prepared,_=prepare_and_receipt(channel,backend)
    entered=threading.Event();result=[]
    def waiting():
        entered.set();result.append(channel.handle(json.dumps(base('wait',request_sha256=prepared['request_sha256']))))
    waiter=threading.Thread(target=waiting);waiter.start();assert entered.wait(2)
    rpc.revoke(JOB);waiter.join(2)
    assert not waiter.is_alive() and result[0]['code']=='grant_revoked'


def prepare_and_receipt(channel, backend, **kw):
    prepared = channel.handle(json.dumps(base(**kw)))
    assert prepared['status'] == 'prepared', prepared
    request = GitApprovalRequest.from_payload(prepared['request'])
    assert prepared['request_sha256'] == request.digest
    return prepared, backend.approve(request)


def pull_request(prepared, receipt, **kw):
    return json.dumps(pull_payload(prepared, receipt, **kw))


def pull_payload(prepared, receipt, **kw):
    return base('pull', request_sha256=prepared['request_sha256'], approval_receipt=receipt, **kw)


@pytest.mark.parametrize('agent', sorted(PUBLIC_AGENT_IDS))
@pytest.mark.parametrize('mode', ['ff-only', 'merge', 'rebase'])
def test_all_named_agents_and_modes_prepare_then_pull(env, agent, mode):
    rpc, backend, _, _ = env
    rpc.issue_grant(grant(agent=agent))
    channel = rpc.channel(JOB)
    prepared, receipt = prepare_and_receipt(channel, backend, agent=agent, mode=mode)
    result = channel.handle(pull_request(prepared, receipt, agent=agent, mode=mode))
    assert result['ok'] and result['status'] == 'completed'
    assert result['outcome'] == backend.outcome
    assert (result['job_id'], result['agent'], result['mode'], result['ref']) == (JOB, agent, mode, REF)
    assert backend.calls[-1] == ('pull', 'alpha', 'origin', REF, mode)
    assert backend.lease_free_on_entry is True


def code(result):
    assert result['ok'] is False and result['status'] == 'denied', result
    return result['code']


def test_push_denied_unconditionally(env):
    rpc, backend, _, _ = env
    rpc.issue_grant(grant(allowed=frozenset({('origin', REF, 'ff-only')})))
    channel = rpc.channel(JOB)
    for payload in (base('push'), {'op': 'push'}, {'op': 'pull', 'push': True},
                    base(allow_push=True), b'{"op":"push","op":"pull"}'):
        raw = payload if isinstance(payload, bytes) else json.dumps(payload)
        assert code(channel.handle(raw)) in {'push_denied', 'invalid_request'}
    assert code(channel.handle(json.dumps(base('push')))) == 'push_denied'
    assert not backend.calls


@pytest.mark.parametrize('field', ['url', 'credential', 'token', 'signing_key', 'argv', 'backend',
                                   'grant', 'capabilities', 'lease', 'repository_path', 'env', 'config'])
def test_worker_cannot_inject_authority(env, field):
    rpc, backend, _, _ = env
    rpc.issue_grant(grant())
    channel = rpc.channel(JOB)
    assert code(channel.handle(json.dumps(base(**{field: 'x'})))) == 'forbidden_field'
    assert not backend.calls


@pytest.mark.parametrize('raw', [b'', b'[]', b'null', b'{', b'{"op":"prepare","op":"prepare"}',
                                 b'{"op":"pull","x":NaN}', b'\xff', 'x' * 70000, '{"op":"prepare"}'])
def test_malformed_requests_rejected(env, raw):
    rpc, backend, _, _ = env
    rpc.issue_grant(grant())
    assert code(rpc.channel(JOB).handle(raw)) == 'invalid_request'
    assert not backend.calls


@pytest.mark.parametrize('change,expected', [
    ({'job_id': OTHER_JOB}, 'job_mismatch'),
    ({'agent': 'codex_review'}, 'agent_mismatch'),
    ({'workspace_id': 'beta'}, 'workspace_mismatch'),
    ({'repository': 'data/nested'}, 'repository_mismatch'),
    ({'remote': 'upstream'}, 'scope_denied'),
    ({'ref': 'refs/heads/other'}, 'scope_denied'),
    ({'mode': 'merge'}, 'scope_denied'),
    ({'ref': 'main'}, 'invalid_request'),
    ({'ref': 'refs/tags/v1'}, 'invalid_request'),
    ({'mode': 'octopus'}, 'invalid_request'),
    ({'remote': 'https://example.invalid/x.git'}, 'invalid_request'),
    ({'version': 2}, 'invalid_request'),
    ({'version': True}, 'invalid_request'),
])
def test_identity_and_scope_binding(env, change, expected):
    rpc, backend, _, _ = env
    rpc.issue_grant(grant(allowed=frozenset({('origin', REF, 'ff-only')})))
    assert code(rpc.channel(JOB).handle(json.dumps({**base(), **change}))) == expected
    assert not backend.calls


def test_cross_job_channel_cannot_use_other_jobs_prepared_request(env):
    rpc, backend, _, _ = env
    rpc.issue_grant(grant())
    rpc.issue_grant(grant(job=OTHER_JOB, agent='codex_review'))
    prepared, receipt = prepare_and_receipt(rpc.channel(JOB), backend)
    other = rpc.channel(OTHER_JOB)
    assert code(other.handle(pull_request(prepared, receipt, job=OTHER_JOB, agent='codex_review'))) == 'not_prepared'
    assert code(other.handle(pull_request(prepared, receipt))) == 'job_mismatch'
    assert [c[0] for c in backend.calls] == ['prepare']


def test_prepared_request_bound_to_exact_scope(env):
    rpc, backend, _, _ = env
    rpc.issue_grant(grant())
    channel = rpc.channel(JOB)
    prepared, receipt = prepare_and_receipt(channel, backend, mode='ff-only')
    assert code(channel.handle(pull_request(prepared, receipt, mode='merge'))) == 'prepared_scope_mismatch'
    wrong = json.dumps(dict(pull_payload(prepared, receipt), request_sha256='0' * 64))
    assert code(channel.handle(wrong)) in {'receipt_mismatch'}
    assert [c[0] for c in backend.calls] == ['prepare']


def test_read_only_grant_rejected(env):
    rpc, backend, _, _ = env
    rpc.issue_grant(grant(capabilities=frozenset({'read'})))
    channel = rpc.channel(JOB)
    assert code(channel.handle(json.dumps(base()))) == 'read_only'
    assert code(channel.handle(json.dumps(base('pull', request_sha256='0' * 64,
                                               approval_receipt='{}')))) == 'read_only'
    assert not backend.calls


def test_stale_job_grant_and_revocation(env):
    rpc, backend, live, clock = env
    rpc.issue_grant(grant())
    channel = rpc.channel(JOB)
    prepared, receipt = prepare_and_receipt(channel, backend)
    live[JOB] = False
    assert code(channel.handle(pull_request(prepared, receipt))) == 'job_not_live'
    live[JOB] = True
    clock.now = NOW + 3600
    assert code(channel.handle(json.dumps(base()))) == 'grant_expired'
    clock.now = NOW
    rpc.revoke(JOB)
    assert code(channel.handle(pull_request(prepared, receipt))) == 'grant_revoked'
    with pytest.raises(PermissionError):
        rpc.channel(JOB)
    assert [c[0] for c in backend.calls] == ['prepare']


def test_liveness_exception_fails_closed(tmp_path):
    clock = Clock()
    def boom(*_):
        raise RuntimeError('x')
    rpc = WorkerGitRPC(FakeBackend(tmp_path, clock), boom, clock=clock)
    rpc.issue_grant(grant())
    assert code(rpc.channel(JOB).handle(json.dumps(base()))) == 'job_not_live'


def test_stale_prepared_and_stale_receipt(env):
    rpc, backend, _, clock = env
    rpc.issue_grant(grant())
    channel = rpc.channel(JOB)
    prepared, receipt = prepare_and_receipt(channel, backend)
    clock.now = NOW + 61
    assert code(channel.handle(pull_request(prepared, receipt))) == 'receipt_stale'
    rpc._ttl = 100
    prepared, _ = prepare_and_receipt(channel, backend)
    request = GitApprovalRequest.from_payload(prepared['request'])
    long_receipt = backend.approve(request, lifetime=300)
    clock.now += 150
    assert code(channel.handle(pull_request(prepared, long_receipt))) == 'prepared_stale'
    assert [c[0] for c in backend.calls] == ['prepare', 'prepare']


def test_receipt_for_another_request_rejected_before_backend(env):
    rpc, backend, _, _ = env
    rpc.issue_grant(grant())
    channel = rpc.channel(JOB)
    prepared, _ = prepare_and_receipt(channel, backend)
    other = GitApprovalRequest.from_payload({**prepared['request'], 'expected_head': 'd' * 40})
    assert code(channel.handle(pull_request(prepared, backend.approve(other)))) == 'receipt_mismatch'
    for junk in ('x', '[]', '{"claims":1,"signature":"x"}', '{"claims":{},"signature":"x"}'):
        assert code(channel.handle(pull_request(prepared, junk))) == 'receipt_invalid'
    assert [c[0] for c in backend.calls] == ['prepare']


def test_forged_signature_denied_by_backend_without_retry(env):
    rpc, backend, _, _ = env
    rpc.issue_grant(grant())
    channel = rpc.channel(JOB)
    prepared, receipt = prepare_and_receipt(channel, backend)
    envelope = json.loads(receipt)
    envelope['signature'] = envelope['signature'][:-2] + ('AA' if not envelope['signature'].endswith('AA') else 'BB')
    result = channel.handle(pull_request(prepared, json.dumps(envelope)))
    assert result['status'] == 'denied' and result['code'] == 'backend_denied'
    assert code(channel.handle(pull_request(prepared, receipt))) == 'replay'


def test_replay_rejected_and_backend_called_once(env):
    rpc, backend, _, _ = env
    rpc.issue_grant(grant())
    channel = rpc.channel(JOB)
    prepared, receipt = prepare_and_receipt(channel, backend)
    assert channel.handle(pull_request(prepared, receipt))['ok']
    assert code(channel.handle(pull_request(prepared, receipt))) == 'replay'
    assert [c[0] for c in backend.calls].count('pull') == 1


@pytest.mark.parametrize('outcome', [
    {'status': 'recovery_required', 'recovery_required': True, 'guard': 'retained', 'nonce': 'n' * 32},
    {'status': 'conflict', 'published': False, 'paths': ['a']},
])
def test_structured_backend_outcomes_preserved_unchanged(env, outcome):
    rpc, backend, _, _ = env
    rpc.issue_grant(grant())
    channel = rpc.channel(JOB)
    prepared, receipt = prepare_and_receipt(channel, backend)
    backend.outcome = outcome
    result = channel.handle(pull_request(prepared, receipt))
    assert result['ok'] and result['outcome'] == outcome


@pytest.mark.parametrize('failure', [RuntimeError('boom'), OSError('disk')])
def test_backend_failure_is_uncertain_and_not_retriable(env, failure):
    rpc, backend, _, _ = env
    rpc.issue_grant(grant())
    channel = rpc.channel(JOB)
    prepared, receipt = prepare_and_receipt(channel, backend)
    backend.error = failure
    result = channel.handle(pull_request(prepared, receipt))
    assert result['status'] == 'uncertain' and result['recovery_required'] is True
    assert 'boom' not in json.dumps(result) and 'disk' not in json.dumps(result)
    assert code(channel.handle(pull_request(prepared, receipt))) == 'replay'


@pytest.mark.parametrize('outcome', [['not', 'dict'], {'x': float('nan')}, {'x': 'y' * 300000}])
def test_unserializable_or_oversized_outcome_is_uncertain(env, outcome):
    rpc, backend, _, _ = env
    rpc.issue_grant(grant())
    channel = rpc.channel(JOB)
    prepared, receipt = prepare_and_receipt(channel, backend)
    backend.outcome = outcome
    backend_dict = backend.pull
    backend.pull = lambda *a: outcome if not isinstance(outcome, dict) else dict(outcome)
    result = channel.handle(pull_request(prepared, receipt))
    assert result['status'] == 'uncertain' and result['recovery_required'] is True
    backend.pull = backend_dict


def test_backend_request_scope_mismatch_refused(env):
    rpc, backend, _, _ = env
    rpc.issue_grant(grant())
    channel = rpc.channel(JOB)
    backend.repository_path = '/srv/ws/other'
    assert code(channel.handle(json.dumps(base()))) == 'request_scope_mismatch'
    backend.repository_path = REPO
    backend.operation = 'fetch'
    assert code(channel.handle(json.dumps(base()))) == 'request_scope_mismatch'


def test_backend_prepare_refusal_is_generic(env):
    rpc, backend, _, _ = env
    rpc.issue_grant(grant())
    backend.prepare = lambda *a: (_ for _ in ()).throw(PermissionError('secret path /x'))
    result = rpc.channel(JOB).handle(json.dumps(base()))
    assert code(result) == 'backend_refused' and 'secret' not in json.dumps(result)


def test_adapter_never_takes_mutation_lease():
    source = open(worker_git_rpc.__file__).read()
    for forbidden in ('serialized_mutation', 'mutation_lease', 'locked_git_request', 'WorkspaceTransaction'):
        assert forbidden not in source.replace('mutation lease', '').replace('mutation transaction/lease', '')


def test_grant_validation():
    for bad in ({'agent': 'mallory'}, {'job_id': 'job_x'}, {'workspace_id': '*'},
                {'repository_path': 'relative'}, {'repository_path': '/a/../b'},
                {'repository': '../x'}, {'repository': '/abs'},
                {'capabilities': frozenset({'push'})}, {'allowed': frozenset()},
                {'allowed': frozenset({('origin', 'refs/tags/x', 'merge')})},
                {'allowed': frozenset({('origin', REF, 'squash')})},
                {'allowed': frozenset({('https://x', REF, 'merge')})}, {'expires_at': 0}):
        with pytest.raises(ValueError):
            grant(**bad)


def test_grant_registry_rules(env):
    rpc, _, _, _ = env
    with pytest.raises(TypeError):
        rpc.issue_grant({'job_id': JOB})
    rpc.issue_grant(grant())
    with pytest.raises(ValueError):
        rpc.issue_grant(grant())
    with pytest.raises(PermissionError):
        rpc.channel(OTHER_JOB)
    with pytest.raises(TypeError):
        WorkerGitRPC(object(), lambda *a: True)
    with pytest.raises(TypeError):
        WorkerGitRPC(FakeBackend.__new__(FakeBackend), None)


def frame(payload):
    body = payload if isinstance(payload, bytes) else json.dumps(payload).encode()
    return struct.pack('>I', len(body)) + body


def test_framed_transport_roundtrip_and_limits(env):
    rpc, backend, _, _ = env
    rpc.issue_grant(grant())
    channel = rpc.channel(JOB)
    out = io.BytesIO()
    channel.serve_frame(io.BytesIO(frame(base())).read, out.write)
    reply = json.loads(out.getvalue()[4:])
    assert struct.unpack('>I', out.getvalue()[:4])[0] == len(out.getvalue()) - 4
    assert reply['status'] == 'prepared'
    out = io.BytesIO()
    channel.serve_frame(io.BytesIO(struct.pack('>I', 10**6)).read, out.write)
    assert json.loads(out.getvalue()[4:])['code'] == 'invalid_request'
    with pytest.raises(EOFError):
        channel.serve_frame(io.BytesIO(struct.pack('>I', 50) + b'{}').read, io.BytesIO().write)


def test_concurrent_receipt_use_dispatches_once(env):
    rpc, backend, _, _ = env
    rpc.issue_grant(grant())
    channel = rpc.channel(JOB)
    prepared, receipt = prepare_and_receipt(channel, backend)
    results = []
    threads = [threading.Thread(target=lambda: results.append(channel.handle(pull_request(prepared, receipt))))
               for _ in range(8)]
    [t.start() for t in threads]
    [t.join() for t in threads]
    assert sum(1 for r in results if r['ok']) == 1
    assert [c[0] for c in backend.calls].count('pull') == 1


@pytest.mark.parametrize('name,value', [
    ('mode', None), ('remote_id', None), ('remote_ref', None),
    ('mode', 'merge'), ('remote_id', 'upstream'), ('remote_ref', 'refs/heads/other')])
def test_canonical_signed_parameters_required_exactly(env, name, value):
    rpc, backend, _, _ = env
    rpc.issue_grant(grant())
    original = backend._request

    def request(workspace_id, remote, ref, mode):
        payload = original(workspace_id, remote, ref, mode).to_payload()
        if value is None:
            del payload['parameters'][name]
        else:
            payload['parameters'][name] = value
        return GitApprovalRequest.from_payload(payload)

    backend._request = request
    result = rpc.channel(JOB).handle(json.dumps(base()))
    assert result['code'] == 'request_scope_mismatch'


@pytest.mark.parametrize('alias', ['full_ref', 'ref', 'remote'])
def test_aliases_do_not_replace_canonical_parameters(env, alias):
    rpc, backend, _, _ = env
    rpc.issue_grant(grant())
    original = backend._request

    def request(workspace_id, remote, ref, mode):
        payload = original(workspace_id, remote, ref, mode).to_payload()
        payload['parameters'][alias] = remote if alias == 'remote' else ref
        del payload['parameters']['remote_ref' if alias != 'remote' else 'remote_id']
        return GitApprovalRequest.from_payload(payload)

    backend._request = request
    assert rpc.channel(JOB).handle(json.dumps(base()))['code'] == 'request_scope_mismatch'


def test_prepared_state_is_bounded_per_job(env):
    rpc, backend, _, _ = env
    rpc.issue_grant(grant())
    channel = rpc.channel(JOB)
    counter = iter(range(10 ** 6))
    original = backend._request

    def request(workspace_id, remote, ref, mode):
        payload = original(workspace_id, remote, ref, mode).to_payload()
        payload['expected_head'] = '%040x' % next(counter)
        return GitApprovalRequest.from_payload(payload)

    backend._request = request
    for _ in range(worker_git_rpc.MAX_PREPARED_PER_JOB * 3):
        assert channel.handle(json.dumps(base()))['status'] == 'prepared'
    assert len(rpc._prepared) == worker_git_rpc.MAX_PREPARED_PER_JOB


def test_dispatched_nonce_never_evicted_or_reset(env):
    rpc, backend, _, _ = env
    rpc.issue_grant(grant())
    channel = rpc.channel(JOB)
    prepared, receipt = prepare_and_receipt(channel, backend)
    assert channel.handle(pull_request(prepared, receipt))['status'] == 'completed'
    # Re-preparing the identical request must not reset the dispatched claim.
    assert channel.handle(json.dumps(base()))['status'] == 'prepared'
    assert channel.handle(pull_request(prepared, receipt))['code'] == 'replay'
    counter = iter(range(10 ** 6))
    original = backend._request

    def request(workspace_id, remote, ref, mode):
        payload = original(workspace_id, remote, ref, mode).to_payload()
        payload['expected_head'] = '%040x' % (next(counter) + 1)
        return GitApprovalRequest.from_payload(payload)

    backend._request = request
    for _ in range(worker_git_rpc.MAX_PREPARED_PER_JOB * 2):
        channel.handle(json.dumps(base()))
    assert channel.handle(pull_request(prepared, receipt))['code'] == 'replay'


def test_full_store_of_dispatched_records_refuses_new_prepare(env, monkeypatch):
    rpc, backend, _, _ = env
    monkeypatch.setattr(worker_git_rpc, 'MAX_PREPARED_PER_JOB', 1)
    rpc.issue_grant(grant())
    channel = rpc.channel(JOB)
    prepared, receipt = prepare_and_receipt(channel, backend)
    assert channel.handle(pull_request(prepared, receipt))['status'] == 'completed'
    backend._request = lambda *a: GitApprovalRequest.from_payload(
        {**GitApprovalRequest.from_payload(prepared['request']).to_payload(), 'expected_head': 'd' * 40})
    assert channel.handle(json.dumps(base()))['code'] == 'prepared_full'


def test_channel_active_tracks_grant_expiry_and_liveness(env):
    rpc, _, live, clock = env
    rpc.issue_grant(grant())
    channel = rpc.channel(JOB)
    assert channel.active()
    live[JOB] = False
    assert not channel.active()
    live[JOB] = True
    clock.now = NOW + 3600
    assert not channel.active()
    clock.now = NOW
    rpc.revoke(JOB)
    assert not channel.active()
