"""Synthetic Wei-only protected configuration update; no sudo/network/services."""
import copy
import importlib.util
import os
from pathlib import Path
import stat

import pytest
import yaml

script = Path(__file__).resolve().parents[2] / 'scripts/repair-a7dev-wei-free.py'
spec = importlib.util.spec_from_file_location('wei_free_operator', script)
operator = importlib.util.module_from_spec(spec)
spec.loader.exec_module(operator)


@pytest.fixture
def fixture(tmp_path):
    ns = {'__name__': 'test_operator_payload'}
    exec(compile(operator.SERVICE_CODE, '<wei-service-code>', 'exec'), ns)
    config, credentials = tmp_path / 'config', tmp_path / 'credentials'
    config.mkdir(mode=0o700)
    credentials.mkdir(mode=0o700)
    (credentials / 'wei-key').write_text('old-paid-key-preserved')
    original = {'enabled': True, 'profile': 'development', 'gateway_user': 'agentporter-dev',
        'production_uid': 1000, 'network_enabled': True,
        'allowed_workspace_roots': [{'path': '/fixture', 'writable': False}],
        'workers': {'wei': {'provider': 'opencode-go', 'model': 'opencode-go/glm-5.3-flash',
            'credentials': {'.config/opencode/wei-key': str(credentials / 'wei-key')},
            'executable': '/immutable/opencode', 'runtime_mounts': []},
            'phil': {'provider': 'github-copilot', 'model': 'unchanged',
                     'credentials': {'config': '/unread/private/phil'}}}}
    path = config / 'development-runtime.yaml'
    path.write_text(yaml.safe_dump(original, sort_keys=False))
    path.chmod(0o600)
    return ns, config, credentials, path, original


def repair(fixture):
    ns, config, credentials, _, _ = fixture
    return ns['repair'](config, credentials, os.getuid(), os.getgid())


def test_proposal_never_invokes_commands(monkeypatch, capsys):
    monkeypatch.setattr('sys.argv', [str(script)])
    monkeypatch.setattr(operator.subprocess, 'run', lambda *a, **k: pytest.fail('subprocess'))
    operator.main()
    assert 'Proposal only' in capsys.readouterr().out


def test_changes_only_wei_and_preserves_backup_and_paid_key(fixture):
    _, config, credentials, path, before = fixture
    raw = path.read_bytes()
    result = repair(fixture)
    after = yaml.safe_load(path.read_bytes())
    expected = copy.deepcopy(before)
    expected['workers']['wei'].update(provider='opencode', model='opencode/glm-5.3-flash-free',
        credentials={'.config/opencode/wei-key': str(credentials / 'free-access')})
    assert after == expected
    assert Path(result['backup']).read_bytes() == raw
    assert (credentials / 'wei-key').read_text() == 'old-paid-key-preserved'
    assert (credentials / 'free-access').read_bytes() == b'public\n'
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert stat.S_IMODE((credentials / 'free-access').stat().st_mode) == 0o600
    assert result['other_workers_changed'] is result['production_changed'] is False
    assert not list(config.glob('.wei-*'))


def test_repeat_is_idempotent(fixture):
    repair(fixture)
    path = fixture[3]
    original = path.read_bytes(), path.stat().st_ino
    assert repair(fixture)['changed'] is False
    assert (path.read_bytes(), path.stat().st_ino) == original


def test_unreviewed_route_preserved(fixture):
    _, _, credentials, path, before = fixture
    before['workers']['wei']['model'] = 'opencode-go/another-paid-model'
    path.write_text(yaml.safe_dump(before))
    original = path.read_bytes()
    with pytest.raises(PermissionError, match='reviewed old/new pair'):
        repair(fixture)
    assert path.read_bytes() == original
    assert not (credentials / 'free-access').exists()


@pytest.mark.parametrize('target', ['development-runtime.yaml', 'free-access'])
def test_symlinks_are_not_followed(fixture, target):
    _, config, credentials, path, _ = fixture
    original = path.read_bytes()
    victim = config.parent / 'unrelated'
    victim.write_bytes(original if target == path.name else b'preserve')
    victim.chmod(0o600)
    destination = config / target if target == path.name else credentials / target
    if destination.exists(): destination.unlink()
    destination.symlink_to(victim)
    with pytest.raises(OSError): repair(fixture)
    assert victim.read_bytes() == (original if target == path.name else b'preserve')


def test_conflicting_marker_is_preserved(fixture):
    path = fixture[3]
    original = path.read_bytes()
    marker = fixture[2] / 'free-access'
    marker.write_text('operator-owned-existing-content')
    marker.chmod(0o600)
    with pytest.raises(PermissionError, match='free-access file differs'): repair(fixture)
    assert path.read_bytes() == original
    assert marker.read_text() == 'operator-owned-existing-content'


def test_public_runtime_is_rejected(fixture):
    path = fixture[3]
    path.chmod(0o644)
    with pytest.raises(PermissionError, match='private regular'): repair(fixture)
    assert stat.S_IMODE(path.stat().st_mode) == 0o644


def test_concurrent_runtime_edit_is_preserved(fixture, monkeypatch):
    ns, config, _, path, _ = fixture
    real_publish = ns['publish_new']
    def racing_publish(fd, name, data):
        real_publish(fd, name, data)
        if name.startswith('development-runtime.before-'):
            path.write_text('concurrent operator edit\n')
    monkeypatch.setitem(ns, 'publish_new', racing_publish)
    with pytest.raises(PermissionError, match='changed concurrently'): repair(fixture)
    assert path.read_text() == 'concurrent operator edit\n'
    assert not list(config.glob('.wei-*'))
