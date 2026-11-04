import importlib.util
import json
import os
import socket
import stat
import struct
import threading
import time
from pathlib import Path

import pytest

from agentporter.git_approvals import GitApprovalRequest
from agentporter.worker_git_rpc import WorkerGitRPC
from agentporter.worker_git_transport import (
    CONTAINER_PATH, MAX_FRAME, SOCKET_NAME, WorkerGitClient, WorkerGitSocket, WorkerGitTransportError)

_spec = importlib.util.spec_from_file_location('_rpc_tests', Path(__file__).with_name('test_worker_git_rpc.py'))
rpc_tests = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(rpc_tests)
JOB, OTHER_JOB = rpc_tests.JOB, rpc_tests.OTHER_JOB


@pytest.fixture
def env(tmp_path):
    clock = rpc_tests.Clock()
    backend = rpc_tests.FakeBackend(tmp_path, clock)
    live = {JOB: True, OTHER_JOB: True}
    rpc = WorkerGitRPC(backend, lambda job, agent, ws: live.get(job, False), clock=clock)
    rpc.issue_grant(rpc_tests.grant())
    rpc.issue_grant(rpc_tests.grant(job=OTHER_JOB))
    sockdir = tmp_path / 'sock'
    sockdir.mkdir(mode=0o700)
    return rpc, backend, live, clock, str(sockdir)


def raw_roundtrip(path, payload, *, read=True):
    conn = socket.socket(socket.AF_UNIX)
    conn.settimeout(5)
    conn.connect(path)
    conn.sendall(payload)
    if not read:
        return conn
    header = conn.recv(4)
    if len(header) < 4:
        conn.close()
        return None
    (size,) = struct.unpack('>I', header)
    data = b''
    while len(data) < size:
        data += conn.recv(size - len(data))
    conn.close()
    return json.loads(data)


def test_roundtrip_prepare_pull_and_socket_mode(env):
    rpc, backend, _, _, sockdir = env
    with WorkerGitSocket(rpc, JOB, sockdir) as service:
        info = os.lstat(service.host_path)
        assert stat.S_ISSOCK(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o600
        assert service.container_path == CONTAINER_PATH == '/run/agentporter-git.sock'
        client = WorkerGitClient(service.host_path)
        prepared = client.request(rpc_tests.base())
        assert prepared['status'] == 'prepared'
        receipt = backend.approve(GitApprovalRequest.from_payload(prepared['request']))
        done = client.request(rpc_tests.pull_payload(prepared, receipt))
        assert done['status'] == 'completed' and done['outcome'] == backend.outcome
        assert client.request(rpc_tests.pull_payload(prepared, receipt))['code'] == 'replay'
    assert not os.path.lexists(os.path.join(sockdir, SOCKET_NAME))


def test_push_denied_over_socket(env):
    rpc, _, _, _, sockdir = env
    with WorkerGitSocket(rpc, JOB, sockdir) as service:
        result = WorkerGitClient(service.host_path).request(rpc_tests.base('push'))
        assert result['code'] == 'push_denied'


def test_socket_is_bound_to_its_own_job_only(env):
    rpc, backend, _, _, sockdir = env
    with WorkerGitSocket(rpc, JOB, sockdir) as service:
        result = WorkerGitClient(service.host_path).request(rpc_tests.base(job=OTHER_JOB))
        assert result['code'] == 'job_mismatch'
        assert backend.calls == []


def test_unknown_job_cannot_create_transport(env):
    rpc, _, _, _, sockdir = env
    with pytest.raises(PermissionError):
        WorkerGitSocket(rpc, 'job_' + '9' * 24, sockdir)


def test_long_host_path_uses_fd_alias(env, tmp_path):
    rpc, _, _, _, _ = env
    deep = tmp_path
    for _ in range(6):
        deep = deep / ('d' * 30)
    deep.mkdir(parents=True, mode=0o700)
    assert len(str(deep / SOCKET_NAME)) > 108
    cwd = os.getcwd()
    with WorkerGitSocket(rpc, JOB, str(deep)) as service:
        assert WorkerGitClient(service.host_path).request(rpc_tests.base())['status'] == 'prepared'
    assert os.getcwd() == cwd


def test_rejects_non_private_symlink_and_relative_directories(env, tmp_path):
    rpc, _, _, _, sockdir = env
    os.chmod(sockdir, 0o750)
    with pytest.raises(WorkerGitTransportError):
        WorkerGitSocket(rpc, JOB, sockdir).start()
    os.chmod(sockdir, 0o700)
    link = tmp_path / 'link'
    link.symlink_to(sockdir)
    with pytest.raises(WorkerGitTransportError):
        WorkerGitSocket(rpc, JOB, str(link)).start()
    with pytest.raises(WorkerGitTransportError):
        WorkerGitSocket(rpc, JOB, 'relative').start()
    with pytest.raises(WorkerGitTransportError):
        WorkerGitSocket(rpc, JOB, str(tmp_path / 'sock' / '..' / 'sock')).start()


def test_rejects_symlink_in_parent_chain(env, tmp_path):
    rpc, _, _, _, sockdir = env
    link = tmp_path / 'viaparent'
    link.symlink_to(tmp_path)
    with pytest.raises(WorkerGitTransportError):
        WorkerGitSocket(rpc, JOB, str(link / 'sock')).start()


def test_refuses_dead_job_and_non_socket_path(env):
    rpc, _, live, _, sockdir = env
    live[JOB] = False
    with pytest.raises(WorkerGitTransportError):
        WorkerGitSocket(rpc, JOB, sockdir).start()
    live[JOB] = True
    Path(sockdir, SOCKET_NAME).write_text('x')
    with pytest.raises(WorkerGitTransportError):
        WorkerGitSocket(rpc, JOB, sockdir).start()
    assert Path(sockdir, SOCKET_NAME).read_text() == 'x'


def test_stale_socket_is_replaced_but_live_owner_is_refused(env):
    rpc, _, _, _, sockdir = env
    stale = socket.socket(socket.AF_UNIX)
    stale.bind(os.path.join(sockdir, SOCKET_NAME))
    stale.close()
    assert os.path.lexists(os.path.join(sockdir, SOCKET_NAME))
    with WorkerGitSocket(rpc, JOB, sockdir) as first:
        with pytest.raises(WorkerGitTransportError):
            WorkerGitSocket(rpc, JOB, sockdir).start()
        assert WorkerGitClient(first.host_path).request(rpc_tests.base())['status'] == 'prepared'


def test_cleanup_does_not_unlink_a_later_owners_replacement(env):
    rpc, _, _, _, sockdir = env
    path = os.path.join(sockdir, SOCKET_NAME)
    service = WorkerGitSocket(rpc, JOB, sockdir).start()
    os.unlink(path)
    replacement = socket.socket(socket.AF_UNIX)
    replacement.bind(path)
    replacement.listen(1)
    try:
        before = os.lstat(path).st_ino
        service.close()
        assert os.lstat(path).st_ino == before
    finally:
        replacement.close()


def test_job_death_and_revocation_close_and_clean_up(env):
    rpc, _, live, _, sockdir = env
    closed = threading.Event()
    service = WorkerGitSocket(rpc, JOB, sockdir, on_close=closed.set).start()
    live[JOB] = False
    assert closed.wait(5)
    assert not os.path.lexists(service.host_path)
    assert not service.running
    with pytest.raises(WorkerGitTransportError):
        WorkerGitClient(service.host_path).request(rpc_tests.base())
    live[JOB] = True
    revoked = WorkerGitSocket(rpc, OTHER_JOB, sockdir).start()
    rpc.revoke(OTHER_JOB)
    deadline = time.time() + 5
    while os.path.lexists(revoked.host_path) and time.time() < deadline:
        time.sleep(0.05)
    assert not revoked.running and not os.path.lexists(revoked.host_path)


def test_oversized_frame_denied_and_closed(env):
    rpc, backend, _, _, sockdir = env
    with WorkerGitSocket(rpc, JOB, sockdir) as service:
        result = raw_roundtrip(service.host_path, struct.pack('>I', MAX_FRAME + 1))
        assert result['code'] == 'invalid_request'
        assert backend.calls == []
        with pytest.raises(WorkerGitTransportError):
            WorkerGitClient(service.host_path).request({'x': 'y' * (MAX_FRAME + 1)})


def test_malformed_frame_and_partial_frame(env):
    rpc, _, _, _, sockdir = env
    with WorkerGitSocket(rpc, JOB, sockdir, io_timeout=0.3) as service:
        body = b'not json'
        assert raw_roundtrip(service.host_path, struct.pack('>I', len(body)) + body)['code'] == 'invalid_request'
        conn = raw_roundtrip(service.host_path, struct.pack('>I', 100) + b'abc', read=False)
        assert conn.recv(4) == b''
        conn.close()


def test_idle_connection_times_out_and_connections_are_bounded(env):
    rpc, _, _, _, sockdir = env
    with WorkerGitSocket(rpc, JOB, sockdir, max_connections=1, io_timeout=0.5) as service:
        idle = raw_roundtrip(service.host_path, b'', read=False)
        time.sleep(0.1)
        extra = raw_roundtrip(service.host_path, b'', read=False)
        assert extra.recv(4) == b''
        extra.close()
        assert idle.recv(4) == b''
        idle.close()
        time.sleep(0.2)
        assert WorkerGitClient(service.host_path).request(rpc_tests.base())['status'] == 'prepared'


def test_frames_per_connection_are_bounded(env):
    rpc, _, _, _, sockdir = env
    with WorkerGitSocket(rpc, JOB, sockdir, max_frames=2) as service:
        body = json.dumps(rpc_tests.base()).encode()
        frame = struct.pack('>I', len(body)) + body
        conn = raw_roundtrip(service.host_path, b'', read=False)
        for _ in range(2):
            conn.sendall(frame)
            (size,) = struct.unpack('>I', conn.recv(4))
            got = b''
            while len(got) < size:
                got += conn.recv(size - len(got))
            assert json.loads(got)['status'] == 'prepared'
        try:
            conn.sendall(frame)
            assert conn.recv(4) == b''
        except (ConnectionResetError, BrokenPipeError):
            pass
        conn.close()


def test_client_rejects_oversized_response(env):
    rpc, _, _, _, sockdir = env
    with WorkerGitSocket(rpc, JOB, sockdir) as service:
        client = WorkerGitClient(service.host_path, max_response=10)
        with pytest.raises(WorkerGitTransportError):
            client.request(rpc_tests.base())


def test_client_times_out_on_silent_server(tmp_path):
    path = str(tmp_path / 'silent.sock')
    server = socket.socket(socket.AF_UNIX)
    server.bind(path)
    server.listen(1)
    try:
        with pytest.raises(WorkerGitTransportError):
            WorkerGitClient(path, timeout=0.3).request({'a': 1})
    finally:
        server.close()


def test_no_tcp_listener_and_close_is_idempotent(env):
    rpc, _, _, _, sockdir = env
    service = WorkerGitSocket(rpc, JOB, sockdir)
    with service:
        assert service._listener.family == socket.AF_UNIX
    service.close()
    with pytest.raises(WorkerGitTransportError):
        service.start()


def test_backend_calls_are_serialized_per_job(env):
    rpc, backend, _, _, sockdir = env
    active = []
    peak = [0]
    original = backend.prepare

    def slow(*args):
        active.append(1)
        peak[0] = max(peak[0], len(active))
        time.sleep(0.1)
        try:
            return original(*args)
        finally:
            active.pop()

    backend.prepare = slow
    with WorkerGitSocket(rpc, JOB, sockdir, max_connections=2) as service:
        threads = [threading.Thread(target=lambda: WorkerGitClient(service.host_path).request(rpc_tests.base()))
                   for _ in range(2)]
        [t.start() for t in threads]
        [t.join(10) for t in threads]
    assert peak[0] == 1


def test_close_with_blocked_backend_does_not_hang(env):
    rpc, backend, _, _, sockdir = env
    release = threading.Event()
    entered = threading.Event()

    def blocked(*args):
        entered.set()
        release.wait(10)
        raise RuntimeError('late')

    backend.prepare = blocked
    service = WorkerGitSocket(rpc, JOB, sockdir).start()
    path = service.host_path
    thread = threading.Thread(target=lambda: _swallow(lambda: WorkerGitClient(path, timeout=5).request(rpc_tests.base())))
    thread.start()
    assert entered.wait(5)
    started = time.time()
    service.close()
    assert time.time() - started < 5
    assert not os.path.lexists(path)
    release.set()
    thread.join(10)


def _swallow(call):
    try:
        call()
    except Exception:
        pass


def _swap_in_owner(path, keep):
    # Park the old inode so the replacement cannot reuse its inode number.
    parked = path + '.parked'
    os.rename(path, parked)
    keep.append(parked)
    owner = socket.socket(socket.AF_UNIX)
    owner.bind(path)
    owner.listen(1)
    keep.append(owner)
    return os.stat(path, follow_symlinks=False)


def test_close_preserves_owner_inserted_after_last_check_before_retire(env):
    rpc, _, _, _, sockdir = env
    path = os.path.join(sockdir, SOCKET_NAME)
    keep = []
    service = WorkerGitSocket(rpc, JOB, sockdir).start()
    seen = []
    service._pre_retire_hook = lambda: seen.append(_swap_in_owner(path, keep))
    service.close()
    assert seen and os.path.lexists(path)
    now = os.stat(path, follow_symlinks=False)
    assert (now.st_dev, now.st_ino) == (seen[0].st_dev, seen[0].st_ino)
    probe = socket.socket(socket.AF_UNIX)
    probe.connect(path)
    probe.close()
    assert os.listdir(os.path.join(sockdir, '.custody')) == []
    keep[-1].close()


def test_stale_retirement_preserves_owner_inserted_before_retire(env):
    rpc, _, _, _, sockdir = env
    path = os.path.join(sockdir, SOCKET_NAME)
    stale = socket.socket(socket.AF_UNIX)
    stale.bind(path)
    stale.close()
    keep, seen = [], []
    service = WorkerGitSocket(rpc, JOB, sockdir)
    service._pre_retire_hook = lambda: seen.append(_swap_in_owner(path, keep))
    with pytest.raises(WorkerGitTransportError):
        service.start()
    now = os.stat(path, follow_symlinks=False)
    assert (now.st_dev, now.st_ino) == (seen[0].st_dev, seen[0].st_ino)
    assert os.listdir(os.path.join(sockdir, '.custody')) == []
    keep[-1].close()


def test_owner_is_retained_in_custody_if_name_retaken_during_restore(env, monkeypatch):
    from agentporter import worker_git_transport as transport
    rpc, _, _, _, sockdir = env
    path = os.path.join(sockdir, SOCKET_NAME)
    service = WorkerGitSocket(rpc, JOB, sockdir).start()
    keep, third = [], []
    real = transport._renameat2_noreplace

    def racing(old_fd, old, new_fd, new):
        if new == SOCKET_NAME:
            owner = socket.socket(socket.AF_UNIX)
            owner.bind(path)
            keep.append(owner)
            third.append(os.stat(path, follow_symlinks=False))
        real(old_fd, old, new_fd, new)

    monkeypatch.setattr(transport, '_renameat2_noreplace', racing)
    service._pre_retire_hook = lambda: _swap_in_owner(path, keep)
    service.close()
    now = os.stat(path, follow_symlinks=False)
    assert (now.st_dev, now.st_ino) == (third[0].st_dev, third[0].st_ino)
    retained = os.listdir(os.path.join(sockdir, '.custody'))
    assert len(retained) == 1
    for owner in keep[1:]:
        owner.close()
