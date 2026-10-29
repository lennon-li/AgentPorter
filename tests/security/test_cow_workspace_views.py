"""Actual FUSE views, original-filesystem publication, and adversarial changes."""
import os
from pathlib import Path
import socket
import subprocess
import threading
import time
from types import SimpleNamespace

import pytest
from tests._support import BWRAP_USABLE

from agentporter.workspace_view_service import WorkspaceViewServer
from agentporter.workspace_views import CowWorkspaceTransaction
from agentporter.workspace_transactions import WorkspaceTransactionError


@pytest.fixture
def cow(tmp_path):
    program = Path(os.environ.get('AGENTPORTER_TEST_FUSE_PROGRAM', '/usr/bin/fuse-overlayfs'))
    if not program.is_file() or not Path('/dev/fuse').exists():
        pytest.skip('Actual FUSE filesystem unavailable')
    root = tmp_path / 'source'; root.mkdir()
    (root / 'file.txt').write_text('before')
    policy = SimpleNamespace(workspaces={'project': {'path': str(root)}},
                             capabilities=lambda _: {'writable': True},
                             check_path=lambda *args: None)
    server = WorkspaceViewServer(policy, tmp_path / 'views', mount_program=program)
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    socket_path = tmp_path / 'socket'
    server.test_socket_path = socket_path
    listener.bind(str(socket_path)); socket_path.chmod(0o600); listener.listen(6)
    listener.settimeout(.1)
    stop = threading.Event()
    handlers = []

    def serve():
        while not stop.is_set():
            try: channel, _ = listener.accept()
            except socket.timeout: continue
            thread = threading.Thread(target=server.handle, args=(channel,))
            handlers.append(thread); thread.start()
    thread = threading.Thread(target=serve); thread.start()
    counter = 0

    def create(**kwargs):
        nonlocal counter
        counter += 1
        return CowWorkspaceTransaction(root, tmp_path / 'transactions', f'task-{counter}',
                                       view_endpoint=socket_path, **kwargs)
    try:
        yield root, create, server
    finally:
        stop.set(); thread.join(timeout=2); listener.close()
        for handler in handlers: handler.join(timeout=12)
        assert not any(handler.is_alive() for handler in handlers)
        assert not list((tmp_path / 'views').glob('view-*'))


def test_whole_workspace_size_does_not_consume_change_budget(cow):
    root, create, _ = cow
    with (root / 'large-data').open('wb') as stream:
        stream.truncate(1024 ** 3)
    for index in range(10005):
        (root / f'entry-{index}').touch()
    tx = create(max_files=20, max_bytes=100)
    view = tx.prepare()
    try:
        assert (view / 'large-data').stat().st_size == 1024 ** 3
        assert (view / 'entry-10004').exists()
        (view / 'file.txt').write_text('after')
        assert (root / 'file.txt').read_text() == 'before'
        assert tx.apply()['written'] == ['file.txt']
        assert (root / 'file.txt').read_text() == 'after'
        assert (root / 'large-data').stat().st_size == 1024 ** 3
    finally: tx.cleanup()


def test_new_nested_files_publish_and_cleanup_is_idempotent(cow):
    root, create, _ = cow
    tx = create(); view = tx.prepare()
    (view / 'new').mkdir(); (view / 'new' / 'sub').mkdir()
    (view / 'new/sub/output').write_text('new data')
    summary = tx.apply()
    assert summary['written'] == ['new/sub/output']
    assert (root / 'new/sub/output').read_text() == 'new data'
    tx.cleanup(); tx.cleanup()


def test_new_executable_retains_creator_execute_access(cow):
    root, create, _ = cow
    tx = create(); view = tx.prepare()
    (view / 'tool.sh').write_text('#!/bin/sh\nexit 0\n'); (view / 'tool.sh').chmod(0o755)
    try:
        tx.apply()
        assert os.access(root / 'tool.sh', os.R_OK | os.W_OK | os.X_OK)
        assert subprocess.run([str(root / 'tool.sh')], check=False).returncode == 0
    finally: tx.cleanup()


@pytest.mark.parametrize('approved', [False, True])
def test_deleted_original_requires_its_own_authorization(cow, approved):
    root, create, _ = cow
    tx = create(allow_delete=approved); view = tx.prepare()
    (view / 'file.txt').unlink()
    try:
        if approved:
            assert tx.apply()['deleted'] == ['file.txt']
            assert not (root / 'file.txt').exists()
        else:
            with pytest.raises(WorkspaceTransactionError): tx.apply()
            assert (root / 'file.txt').read_text() == 'before'
    finally: tx.cleanup()


@pytest.mark.parametrize('kind', ['symlink', 'hardlink', 'mode', 'git', 'protected', 'concurrent'])
def test_invalid_write_set_never_changes_original(cow, kind):
    root, create, _ = cow
    tx = create(protected_paths=['protected'])
    view = tx.prepare()
    (view / 'file.txt').write_text('after')
    if kind == 'symlink': (view / 'escape').symlink_to('/outside')
    elif kind == 'hardlink': os.link(view / 'file.txt', view / 'alias')
    elif kind == 'mode': (view / 'file.txt').chmod(0o777)
    elif kind == 'git': (view / '.git').mkdir()
    elif kind == 'protected': (view / 'protected').write_text('forbidden')
    else: (root / 'file.txt').write_text('external')
    try:
        with pytest.raises(WorkspaceTransactionError): tx.apply()
        assert (root / 'file.txt').read_text() == ('external' if kind == 'concurrent' else 'before')
    finally: tx.cleanup()


def test_opaque_recreated_directory_does_not_hide_unapproved_deletion(cow):
    root, create, _ = cow
    (root / 'dir').mkdir(); (root / 'dir/keep').write_text('keep')
    tx = create(); view = tx.prepare()
    (view / 'dir/keep').unlink(); (view / 'dir').rmdir(); (view / 'dir').mkdir()
    (view / 'dir/new').write_text('new')
    try:
        with pytest.raises(WorkspaceTransactionError): tx.apply()
        assert (root / 'dir/keep').read_text() == 'keep'
        assert not (root / 'dir/new').exists()
    finally: tx.cleanup()


def test_concurrent_creation_is_not_overwritten(cow):
    root, create, _ = cow
    tx = create(); view = tx.prepare()
    (view / 'new').write_text('job')
    (root / 'new').write_text('external')
    try:
        with pytest.raises(WorkspaceTransactionError): tx.apply()
        assert (root / 'new').read_text() == 'external'
    finally: tx.cleanup()


def test_publication_preserves_effective_named_acl(cow):
    root, create, _ = cow
    subprocess.run(['setfacl', '-m', 'u:12345:rwx,m::r--', str(root / 'file.txt')], check=True)
    tx = create(); view = tx.prepare()
    (view / 'file.txt').write_text('after')
    try:
        tx.apply()
        value = subprocess.run(['getfacl', '-cpn', str(root / 'file.txt')], check=True,
                               capture_output=True, text=True).stdout
        assert 'user:12345:r--' in value
        assert '#effective:rwx' not in value
    finally: tx.cleanup()


def test_view_server_rejects_unregistered_root(cow, tmp_path):
    _, _, server = cow
    left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    thread = threading.Thread(target=server.handle, args=(right,)); thread.start()
    try:
        left.send(b'{"operation":"create","workspace_root":"/"}')
        assert b'denied' in left.recv(4096)
    finally: left.close(); thread.join(timeout=2)


def test_cancel_discards_all_changes(cow):
    root, create, _ = cow
    tx = create(); view = tx.prepare()
    (view / 'file.txt').write_text('after')
    tx.cleanup()
    assert (root / 'file.txt').read_text() == 'before'


@pytest.mark.skipif(not BWRAP_USABLE, reason="Bubblewrap network namespaces unavailable on this host")
def test_hidden_view_mount_never_runs_model_against_empty_backing_directory(cow, tmp_path):
    from agentporter.agents.development import DevelopmentRuntime
    root, create, _ = cow
    tx = create()
    view = tx.prepare()
    empty = tmp_path / 'unmounted-backing'; empty.mkdir()
    runtime = DevelopmentRuntime(tmp_path / 'config', tmp_path / 'jobs', None)
    launch = runtime._build('fixture', {},
        {'executable': str(Path('/usr/bin/python3').resolve()), 'credentials': {}},
        view, True, ['/usr/bin/python3', '-c', "print('MODEL_WAS_RUN')"],
        source_workspace=root, workspace_descriptor=tx.view_descriptor)
    try:
        # Reproduce the mount namespace bug: canonical path resolves to the
        # underlying directory instead of the descriptor's FUSE filesystem.
        for index, argument in enumerate(launch.command):
            if argument == '--bind' and launch.command[index + 2] == '/workspace':
                launch.command[index + 1] = str(empty)
        result = subprocess.run(launch.command, pass_fds=launch.pass_fds,
                                capture_output=True, text=True, timeout=10)
        assert result.returncode != 0
        assert 'Private workspace mount identity mismatch' in result.stderr
        assert 'MODEL_WAS_RUN' not in result.stdout
        assert (root / 'file.txt').read_text() == 'before'
    finally:
        launch.cleanup()
        tx.cleanup()


@pytest.mark.parametrize('control', ['external', 'invalid', 'missing'])
@pytest.mark.skipif(not BWRAP_USABLE, reason="Bubblewrap network namespaces unavailable on this host")
def test_private_code_edits_hide_external_and_inert_git_control_files(cow, tmp_path, control):
    from agentporter.agents.development import DevelopmentRuntime
    root, create, _ = cow
    external = tmp_path / 'external-git'; external.mkdir()
    (external / 'config').write_text('external metadata remains private')
    original = ('not a git control pointer' if control == 'invalid' else
                'gitdir: ' + str(external if control == 'external' else root / 'missing'))
    (root / '.git').write_text(original)
    tx = create(); view = tx.prepare()
    runtime = DevelopmentRuntime(tmp_path / 'config', tmp_path / 'jobs', None)
    code = """from pathlib import Path
assert Path('.git').read_text() == ''
try: Path('.git').write_text('forbidden')
except OSError: pass
else: raise AssertionError('Git control file was writable')
Path('file.txt').write_text('after')
"""
    launch = runtime._build('fixture', {},
        {'executable': str(Path('/usr/bin/python3').resolve()), 'credentials': {}},
        view, True, ['/usr/bin/python3', '-c', code], source_workspace=root,
        workspace_descriptor=tx.view_descriptor)
    try:
        result = subprocess.run(launch.command, pass_fds=launch.pass_fds,
                                capture_output=True, text=True, timeout=10)
        assert result.returncode == 0, result.stderr
        assert tx.apply()['written'] == ['file.txt']
        assert (root / 'file.txt').read_text() == 'after'
        assert (root / '.git').read_text() == original
        assert (external / 'config').read_text() == 'external metadata remains private'
    finally:
        launch.cleanup(); tx.cleanup()


@pytest.mark.skipif(not BWRAP_USABLE, reason="Bubblewrap network namespaces unavailable on this host")
def test_real_delegation_namespace_edits_view_and_preserves_git_and_secrets(cow, monkeypatch, tmp_path):
    from agentporter.agents.development import DevelopmentRuntime
    from agentporter.scoped_approvals import VerifiedGrant
    from agentporter.task_authorization import ACTIVE_GRANT
    from agentporter.workspaces.registry import WorkspaceRegistry
    from agentporter.workspace_policy import SHARED_POLICY_PATH
    import agentporter.workspace_views as views
    root, _, server = cow
    monkeypatch.setattr(views, 'endpoint', lambda: server.test_socket_path)
    (root / '.git').mkdir(); (root / '.git/config').write_text('git-control')
    (root / '.env').write_text('private-data')
    (root / 'nested').mkdir(); (root / 'nested/.git').mkdir()
    (root / 'nested/.git/config').write_text('nested-control')
    registry = WorkspaceRegistry({'project': {'path': str(root), 'allow_agent_dispatch': True}})
    registry.workspace_policy = server.policy
    server.policy.protected_paths = ()
    runtime = DevelopmentRuntime(tmp_path / 'config', tmp_path / 'jobs', registry)
    config = {'service_unit': 'agentporter-worker.service', 'workspace_policy_file': str(SHARED_POLICY_PATH)}
    spec = {'executable': str(Path('/usr/bin/python3').resolve()), 'credentials': {}}
    monkeypatch.setattr(runtime, '_verified', lambda _: (config, spec))
    monkeypatch.setattr(runtime, '_workspace', lambda *args: root)
    claims = {'workspace_root': str(root), 'agent': 'fixture', 'operations': ['write'],
              'expires_at': int(time.time()) + 60}
    code = """from pathlib import Path
import os
for name in os.listdir('/proc/self/fd'):
    if int(name) <= 2: continue
    try: os.fstat(int(name))
    except OSError: continue
    raise AssertionError('host descriptor leaked into the model process')
assert 'NoNewPrivs:\\t1' in Path('/proc/self/status').read_text()
assert Path('.git/config').read_text() == 'git-control'
assert Path('nested/.git/config').read_text() == 'nested-control'
assert Path('.env').read_text() == ''
for name in ['.git/config','nested/.git/config']:
    try: Path(name).write_text('forbidden')
    except OSError: pass
    else: raise AssertionError('metadata writable')
Path('file.txt').write_text('after')
"""
    token = ACTIVE_GRANT.set(VerifiedGrant(claims))
    try: launch = runtime.prepare('fixture', str(root), True, ['/usr/bin/python3', '-c', code])
    finally: ACTIVE_GRANT.reset(token)
    try:
        result = subprocess.run(launch.command, pass_fds=launch.pass_fds, capture_output=True,
                                text=True, timeout=10)
        assert result.returncode == 0, result.stderr
        assert (root / 'file.txt').read_text() == 'before'
        launch.finalize(True)
        assert (root / 'file.txt').read_text() == 'after'
        assert (root / '.git/config').read_text() == 'git-control'
        assert (root / '.env').read_text() == 'private-data'
    finally: launch.cleanup()


@pytest.mark.parametrize('asynchronous', [False, True])
@pytest.mark.skipif(not BWRAP_USABLE, reason="Bubblewrap network namespaces unavailable on this host")
def test_actual_direct_execution_uses_private_view_and_publishes_after_exit(cow, monkeypatch, tmp_path, asynchronous):
    from agentporter.sandbox.bubblewrap import BubblewrapSandbox
    from agentporter.tools.execution import create_execution_tools
    from agentporter.tools.jobs import JobManager
    from agentporter.scoped_approvals import VerifiedGrant
    from agentporter.task_authorization import ACTIVE_GRANT
    from agentporter.workspaces.registry import WorkspaceRegistry
    import agentporter.workspace_views as views
    root, _, server = cow
    monkeypatch.setattr(views, 'endpoint', lambda: server.test_socket_path)
    (root / '.git').mkdir(); (root / '.git/config').write_text('original')
    registry = WorkspaceRegistry({'project': {'path': str(root)}})
    registry.workspace_policy = server.policy
    server.policy.protected_paths = ()
    state = tmp_path / 'jobs'
    manager = JobManager(state)
    sandbox = BubblewrapSandbox(state)
    class Lease:
        def command(self, command): return command
        def close(self): pass
        def terminate(self): pass
    resources = SimpleNamespace(create=Lease)
    sandbox.resources = resources; manager.resources = resources
    run, start = create_execution_tools(registry, sandbox, manager)
    token = ACTIVE_GRANT.set(VerifiedGrant({'workspace_root': str(root), 'operations': ['write']}))
    code = """from pathlib import Path
assert Path('.git/config').read_text() == 'original'
try: Path('.git/config').write_text('forbidden')
except OSError: pass
else: raise AssertionError('Git metadata writable')
Path('file.txt').write_text('after')
"""
    try:
        result = (start if asynchronous else run)('project', ['/usr/bin/python3', '-c', code], read_only=False)
    finally: ACTIVE_GRANT.reset(token)
    if asynchronous:
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            status = manager.get_status(result['job_id'])
            if status['status'] != 'running': break
            time.sleep(.01)
        assert status['status'] == 'completed', status
    else:
        assert result['exit_code'] == 0, result
    assert (root / 'file.txt').read_text() == 'after'
    assert (root / '.git/config').read_text() == 'original'
