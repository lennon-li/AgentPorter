"""Synthetic-only checks of the fixed A7Dev permission repair boundary."""
import errno
import importlib.util
import os
from pathlib import Path
import stat
import subprocess
from types import SimpleNamespace

import pytest


@pytest.fixture
def launcher():
    path = Path(__file__).resolve().parents[2] / 'scripts/repair-a7dev-directory-access.py'
    spec = importlib.util.spec_from_file_location('a7dev_access_repair', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def bootstrap(launcher):
    namespace = {'__name__': 'synthetic_bootstrap'}
    exec(compile(launcher.BOOTSTRAP, '<fixed-bootstrap>', 'exec'), namespace)
    return namespace


def account():
    return SimpleNamespace(pw_name='agentporter-dev', pw_uid=994, pw_gid=981)


def directory_info(mode=0o710, uid=0, gid=981):
    return SimpleNamespace(st_mode=stat.S_IFDIR | mode, st_uid=uid, st_gid=gid, st_dev=1, st_ino=123)


def no_acl(*_):
    raise OSError(errno.ENODATA, 'No access ACL')


def test_exact_policy_opener_requires_read_permission_on_traversable_ancestor(tmp_path, monkeypatch):
    from agentporter.scoped_https import ScopedPublicHTTPSPolicy

    if os.geteuid() == 0:
        pytest.skip('Root bypasses the DAC permission failure being tested')
    ancestor = tmp_path / 'service-private-data'
    config = ancestor / 'config'
    config.mkdir(parents=True)
    config.chmod(0o700)
    original_fstat = os.fstat

    def trusted_ownership(fd):
        fields = list(original_fstat(fd))
        fields[4] = 0
        return os.stat_result(fields)

    # Metadata ownership is simulated; actual open permissions stay enforced.
    monkeypatch.setattr(os, 'fstat', trusted_ownership)
    ancestor.chmod(0o100)
    try:
        assert config.is_dir()  # execute-only traversal really works
        with pytest.raises(PermissionError):
            ScopedPublicHTTPSPolicy._open_trusted_directory(config)
        ancestor.chmod(0o500)  # same read+execute requirement as service group 050
        fd = ScopedPublicHTTPSPolicy._open_trusted_directory(config)
        os.close(fd)
    finally:
        ancestor.chmod(0o700)


@pytest.mark.parametrize('mode,uid,gid,acl', [
    (0o711, 0, 981, False), (0o770, 0, 981, False), (0o750, 994, 981, False),
    (0o710, 0, 1000, False), (0o710, 0, 981, True),
])
def test_data_guard_rejects_unexpected_mode_owner_group_and_acl(bootstrap, mode, uid, gid, acl):
    bootstrap['os'] = SimpleNamespace(fstat=lambda _: directory_info(mode, uid, gid),
                                      getxattr=(lambda *_: b'acl') if acl else no_acl)
    with pytest.raises(PermissionError):
        bootstrap['validate_data'](101, account())


@pytest.mark.parametrize('unexpected', ['explicit_member', 'primary_member', 'supplementary_group'])
def test_service_group_must_be_exclusive(bootstrap, unexpected):
    service = account()
    owner = SimpleNamespace(pw_name='operator', pw_uid=1000, pw_gid=1000)
    rows = [service, owner]
    if unexpected == 'primary_member':
        rows.append(SimpleNamespace(pw_name='other', pw_gid=981))
    bootstrap['pwd'] = SimpleNamespace(getpwnam=lambda name: service if name == 'agentporter-dev' else owner,
                                       getpwall=lambda: rows)
    bootstrap['grp'] = SimpleNamespace(getgrnam=lambda _: SimpleNamespace(gr_gid=981, gr_mem=['other'] if unexpected == 'explicit_member' else []))
    bootstrap['os'] = SimpleNamespace(getgrouplist=lambda *_: [981, 27] if unexpected == 'supplementary_group' else [981])
    with pytest.raises(PermissionError, match='exclusive and private'):
        bootstrap['private_account']()


@pytest.mark.parametrize('key_mode,key_uid', [(stat.S_IFREG | 0o644, 994), (stat.S_IFLNK | 0o777, 994), (stat.S_IFREG | 0o600, 1000)])
def test_existing_key_guard_checks_metadata_only(bootstrap, key_mode, key_uid):
    opened = []

    def open_fd(name, flags, *, dir_fd):
        opened.append((name, flags, dir_fd))
        return 2 if name == 'config' else 3

    fake_os = SimpleNamespace(open=open_fd, close=lambda _: None, O_RDONLY=os.O_RDONLY,
                              O_DIRECTORY=os.O_DIRECTORY, O_NOFOLLOW=os.O_NOFOLLOW, O_PATH=os.O_PATH,
                              fstat=lambda fd: directory_info(0o700, 994) if fd == 2 else SimpleNamespace(st_mode=key_mode, st_uid=key_uid, st_gid=981))
    bootstrap['os'] = fake_os
    with pytest.raises(PermissionError, match='gateway key metadata'):
        bootstrap['existing_private_key'](1, account())
    assert opened == [('config', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, 1),
                      ('secrets.env', os.O_PATH | os.O_NOFOLLOW, 2)]
    assert not hasattr(fake_os, 'read')


@pytest.mark.parametrize('starting_mode,fail_phase', [(0o710, None), (0o750, None), (0o710, 'probe'), (0o710, 'health')])
def test_fixed_bootstrap_mutates_only_data_mode_and_controls_only_development(bootstrap, starting_mode, fail_phase):
    effects = []
    current_mode = [starting_mode]
    fake_os = SimpleNamespace(geteuid=lambda: 0,
                              umask=lambda value: effects.append(('umask', value)),
                              fstat=lambda _: directory_info(current_mode[0]), getxattr=no_acl,
                              close=lambda fd: effects.append(('close', fd)))

    def chmod(fd, mode):
        assert fd == 101
        effects.append(('chmod', fd, mode))
        current_mode[0] = mode

    def run(command, **kwargs):
        effects.append(('run', command, kwargs))
        if command[0] == '/usr/sbin/runuser' and fail_phase == 'probe':
            raise subprocess.CalledProcessError(1, command)
        return SimpleNamespace(returncode=0)

    def check_health():
        effects.append(('health',))
        if fail_phase == 'health':
            raise RuntimeError('synthetic unhealthy service')

    fake_os.fchmod = chmod
    bootstrap.update(os=fake_os, sys=SimpleNamespace(flags=SimpleNamespace(isolated=True)),
                     private_account=account, installed_interpreter=lambda: '/trusted/installed/venv/bin/python',
                     existing_private_key=lambda fd, _: effects.append(('key_metadata', fd)),
                     trusted_directory=lambda path: 101 if path == '/var/lib/agentporter-dev' else pytest.fail(path),
                     subprocess=SimpleNamespace(run=run, DEVNULL=subprocess.DEVNULL), healthy=check_health)
    if fail_phase:
        with pytest.raises((subprocess.CalledProcessError, RuntimeError)):
            bootstrap['main']()
    else:
        bootstrap['main']()
    assert current_mode[0] == 0o750
    mutations = [row for row in effects if row[0] == 'chmod']
    assert mutations == ([('chmod', 101, 0o750)] if starting_mode == 0o710 else [])
    calls = [row for row in effects if row[0] == 'run']
    assert calls[0][1] == ['/usr/bin/systemctl', 'stop', 'agentporter-development.service']
    child = calls[1]
    assert child[1][:6] == ['/usr/sbin/runuser', '-u', 'agentporter-dev', '--', '/usr/bin/env', '-i']
    assert child[1][-4:] == ['-I', '-B', '-c', bootstrap['PROBE']]
    assert 'create_asgi_app(Config(' in child[1][-1]
    assert 'uvicorn' not in child[1][-1]
    assert child[2]['stdout'] == child[2]['stderr'] == subprocess.DEVNULL
    assert child[2]['cwd'] == '/var/lib/agentporter-dev/home'
    assert ('umask', 0o077) in effects
    systemctl = [row[1] for row in calls if row[1][0] == '/usr/bin/systemctl']
    expected = [['/usr/bin/systemctl', 'stop', 'agentporter-development.service']]
    if fail_phase != 'probe':
        expected.append(['/usr/bin/systemctl', 'restart', 'agentporter-development.service'])
    if fail_phase:
        expected.append(['/usr/bin/systemctl', 'stop', 'agentporter-development.service'])
    assert systemctl == expected


@pytest.mark.parametrize('restart_each_check', [False, True])
def test_health_requires_stable_pid_and_restart_count_without_redirects(bootstrap, restart_each_check):
    ticks = [0]
    samples = []
    bootstrap['time'] = SimpleNamespace(monotonic=lambda: ticks[0], sleep=lambda _: ticks.__setitem__(0, ticks[0] + 1))

    class Response:
        status = 200
        def __enter__(self): return self
        def __exit__(self, *_): pass
        def read(self, size):
            assert size == 1025
            return b'{"status":"healthy"}'

    def open_local(url, timeout):
        assert url == 'http://127.0.0.1:8876/health' and timeout == 2
        return Response()

    def build_opener(proxy, redirects):
        assert proxy.proxies == {}
        assert redirects.redirect_request(None, None, None, None, None, None) is None
        return SimpleNamespace(open=open_local)

    bootstrap['urllib'] = SimpleNamespace(request=SimpleNamespace(
        build_opener=build_opener, ProxyHandler=bootstrap['urllib'].request.ProxyHandler,
        HTTPRedirectHandler=bootstrap['urllib'].request.HTTPRedirectHandler))

    def run(command, **kwargs):
        assert command == ['/usr/bin/systemctl', 'show', 'agentporter-development.service', '--property=ActiveState,MainPID,NRestarts']
        samples.append(command)
        restarts = ticks[0] if restart_each_check else 0
        return SimpleNamespace(stdout=f'ActiveState=active\nMainPID=1234\nNRestarts={restarts}\n')

    bootstrap['subprocess'] = SimpleNamespace(run=run, DEVNULL=subprocess.DEVNULL, PIPE=subprocess.PIPE, SubprocessError=subprocess.SubprocessError)
    if restart_each_check:
        with pytest.raises(RuntimeError, match='bounded check'):
            bootstrap['healthy']()
        assert ticks[0] == 30
    else:
        bootstrap['healthy']()
        assert len(samples) == 3


def test_launcher_uses_only_fixed_isolated_sudo_bootstrap(launcher, monkeypatch):
    calls = []
    monkeypatch.setattr(launcher.os, 'geteuid', lambda: 1000)
    monkeypatch.setattr(launcher.subprocess, 'run', lambda *args, **kwargs: calls.append((args, kwargs)))
    launcher.main()
    assert calls == [((['/usr/bin/sudo', '/usr/bin/python3', '-I', '-B', '-c', launcher.BOOTSTRAP],), {'check': True})]
