import importlib.util
import json
import os
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest


@pytest.fixture
def installer():
    path = Path(__file__).parents[2] / 'scripts/install-production-workspace-policy.py'
    spec = importlib.util.spec_from_file_location('sealed_permission_installer_test', path)
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


def test_unprivileged_installation_is_rejected_before_system_mutation(installer, tmp_path, monkeypatch):
    monkeypatch.setattr(installer.os, 'geteuid', lambda: 1000)
    with pytest.raises(RuntimeError, match='sudo'):
        installer.Installation(tmp_path)


def test_runtime_upgrade_retains_identical_helper_and_rejects_changed_unit(installer, tmp_path):
    home = tmp_path / 'home'; units = home / '.config/systemd/user'; units.mkdir(parents=True)
    stage = tmp_path / 'stage'; (stage / 'examples').mkdir(parents=True)
    name = 'agentporter-workspace-views.service'
    body = b'[Service]\nExecStart=/reviewed/helper\n'
    (stage / 'examples' / name).write_bytes(body)
    target = units / name; target.write_bytes(body); target.chmod(0o644)
    state = SimpleNamespace(home=home, stage=stage, user=SimpleNamespace(pw_uid=os.getuid(), pw_gid=os.getgid()), saved_units={})
    before = target.stat().st_ino
    installer.Installation.install_unit(state, name, user=True)
    assert not state.saved_units and target.stat().st_ino == before
    target.write_bytes(body + b'Environment=UNREVIEWED=1\n')
    with pytest.raises(RuntimeError, match='unexpected view-helper'):
        installer.Installation.install_unit(state, name, user=True)


def test_listener_ownership_uses_the_kernel_socket_inode(installer):
    import socket
    with socket.socket() as listener:
        listener.bind(('127.0.0.1', 0)); listener.listen()
        port = listener.getsockname()[1]
        assert installer.owns_listener(os.getpid(), port)
        assert not installer.owns_listener(2147483647, port)


def test_package_commands_find_required_system_helpers_with_sanitized_path(installer, monkeypatch):
    monkeypatch.setenv('PATH', '/missing')
    result = installer.command(['/bin/sh', '-c', 'command -v ldconfig && command -v start-stop-daemon'])
    helpers = result.stdout.splitlines()
    assert len(helpers) == 2
    assert all(Path(helper).is_file() and os.access(helper, os.X_OK) for helper in helpers)


def test_package_failure_reports_actionable_stderr_without_stdout(installer):
    with pytest.raises(RuntimeError, match='sh exited 2: missing package helper') as failure:
        installer.command(['/bin/sh', '-c',
                           'echo private-output; echo "missing package helper" >&2; exit 2'],
                          report_stderr=True)
    assert 'private-output' not in str(failure.value)


def test_config_preflight_failure_leaves_running_production_untouched(installer, tmp_path):
    state = object.__new__(installer.Installation)
    commands = []
    def systemctl(*args):
        commands.append(args)
        return SimpleNamespace(stdout='inactive' if args[1] == 'agentporter-development.service' else 'active')
    def build(home, *, require_stopped=True):
        assert home == tmp_path and require_stopped is False
        raise ValueError('invalid existing control')
    state.systemctl = systemctl
    state.userctl = lambda *args: SimpleNamespace(stdout='123')
    state.api = lambda _: {'pid': 123, 'loaded_fingerprint': 'original'}
    state.manifest = {'gateway_fingerprint': 'original'}
    state.home = tmp_path
    state.health = lambda _: None
    state.idle = lambda: None
    state.save_links = lambda: None
    state.migration = SimpleNamespace(build=build, fingerprint=lambda _: 'plan')
    with pytest.raises(ValueError, match='invalid existing control'):
        state.execute()
    assert commands and all(args[0] == 'show' for args in commands)


def test_existing_attempt_journal_is_rejected_before_stopping_production(installer, tmp_path):
    journal = tmp_path / 'existing-journal'; journal.mkdir()
    state = object.__new__(installer.Installation)
    commands = []
    def systemctl(*args):
        commands.append(args)
        return SimpleNamespace(stdout='inactive' if args[1] == 'agentporter-development.service' else 'active')
    state.systemctl = systemctl
    state.userctl = lambda *args: SimpleNamespace(stdout='123')
    state.api = lambda _: {'pid': 123, 'loaded_fingerprint': 'original'}
    state.manifest = {'gateway_fingerprint': 'original', 'artifact_id': 'attempt-one'}
    state.home = tmp_path
    state.health = lambda _: None
    state.idle = lambda: None
    state.save_links = lambda: None
    state.migration = SimpleNamespace(build=lambda *args, **kwargs: {},
        fingerprint=lambda _: 'plan', recovery_path=lambda *args: journal)
    with pytest.raises(RuntimeError, match='configuration recovery attempt already exists'):
        state.execute()
    assert commands and all(args[0] == 'show' for args in commands)


@pytest.mark.parametrize('worker', [False, True])
@pytest.mark.parametrize('relative_python', [False, True])
def test_candidate_clone_preserves_base_and_uses_explicit_artifact_provenance(installer, tmp_path, worker, relative_python, request):
    base = tmp_path / 'base'
    site = base / 'venv/lib/python3.13/site-packages'
    (site / 'agentporter').mkdir(parents=True)
    (site / 'agentporter/__init__.py').write_text('old code')
    (site / 'agentporter_development.pth').write_text(str(base / 'src') + '\n')
    (base / 'venv/bin').mkdir()
    if relative_python:
        (base / 'python/bin').mkdir(parents=True)
        (base / 'python/bin/python3.13').symlink_to('/usr/bin/python3')
    original_link = '../../python/bin/python3.13' if relative_python else '/usr/bin/python3'
    (base / 'venv/bin/python').symlink_to(original_link)
    (base / 'venv/lib64').symlink_to('lib')
    stage = tmp_path / 'packet'; (stage / 'source/agentporter').mkdir(parents=True)
    (stage / 'source/agentporter/__init__.py').write_text('new code')
    (stage / 'scripts').mkdir()
    (stage / 'scripts/validate-production-workspace-writes.py').write_text('validation code')
    state = SimpleNamespace(stage=stage, manifest={'artifact_id': 'uncommitted-artifact',
                                                  'package_fingerprint': 'a' * 64})
    target = tmp_path / 'candidate'
    def unlock_fixture():
        for fixture in (target, base):
            if fixture.exists():
                fixture.chmod(0o700)
                for path in fixture.rglob('*'):
                    if path.is_dir() and not path.is_symlink(): path.chmod(0o700)
    request.addfinalizer(unlock_fixture)
    for path in [base / 'venv', *(base / 'venv').rglob('*')]:
        if path.is_dir() and not path.is_symlink(): path.chmod(0o555)
    installer.Installation.clone_release(state, base, target, os.getuid(), os.getgid(), worker=worker)
    assert (site / 'agentporter/__init__.py').read_text() == 'old code'
    assert (target / 'venv/lib/python3.13/site-packages/agentporter/__init__.py').read_text() == 'new code'
    assert (target / 'venv/lib/python3.13/site-packages/agentporter_development.pth').read_text() == str(target / 'src') + '\n'
    manifest = json.loads((target / 'RELEASE.json').read_text())
    assert 'commit' not in manifest
    assert manifest['runtime_dependency'] == str(base)
    assert 'uncommitted' in manifest['artifact_source']
    assert (target / 'venv/bin/python').is_symlink()
    assert (base / 'venv/bin/python').readlink().as_posix() == original_link
    assert (target / 'venv/lib64').resolve() == target / 'venv/lib'
    assert subprocess.run([str(target / 'venv/bin/python'), '--version'], capture_output=True).returncode == 0
    assert not (target / 'src/agentporter/__init__.py').stat().st_mode & 0o222
    if worker: assert (target / 'operator-checks/validate-production-workspace-writes.py').is_file()
