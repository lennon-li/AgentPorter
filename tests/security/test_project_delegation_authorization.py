"""Synthetic security checks: no service/config/credential/provider access."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import stat

import pytest
import yaml


@pytest.fixture
def helper(monkeypatch):
    source = Path(__file__).resolve().parents[2] / 'scripts/authorize-a7dev-project-delegation.py'
    spec = importlib.util.spec_from_file_location('project_authorization', source)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    monkeypatch.setattr(module.os.path, 'realpath', lambda p: str(p))
    monkeypatch.setattr(module.Path, 'is_dir', lambda p: True)
    return module


@pytest.fixture
def baseline(helper, monkeypatch):
    rows = {name: {'path': root, 'writable': True, 'allow_execute': False,
                   'allow_agent_dispatch': False, 'allow_git': True,
                   'unrelated_setting': 'preserved'} for name, root in helper.EXPECTED_ROOTS.items()}
    policy = {'version': 1, 'workspaces': {}}
    for name, row in rows.items():
        operations = ['read', 'git_read']
        if name not in helper.PROTECTED:
            operations += ['write', 'exec']
        if name in ('cranary', 'agentporter-dev'):
            operations.append('dispatch')
        if name == 'cranary':
            operations.append('https')
        policy['workspaces'][name] = {'path': row['path'], 'operations': operations}
    release = Path('/opt/agentporter-development/versions/20261021T212000.000019Z')
    runtime = {'allowed_workspace_roots': [
        {'path': rows[n]['path'], 'writable': True}
        for n in ('PAGe', 'agentporter-dev', 'cranary', 'insider', 'm3', 'm3-poc', 'obsidian', 'shiny')],
        'workers': {'wei': {'model': 'opencode/glm-5.3-flash-free', 'credentials': {'token': '/fixture/untouched'}},
                    'jax': {'executable': str(release / 'cli/jax/codex')}},
        'network_enabled': True, 'egress_policy': 'provider_origin',
        'unrelated_limits': {'memory': 123}}
    values = (policy, {'workspaces': rows, 'unrelated': 'keep'}, runtime)
    bodies = {name: yaml.safe_dump(value, sort_keys=False).encode() for name, value in zip(helper.FILES, values)}
    bodies[helper.HTTPS] = b'version: 2\nworkspaces: [cranary]\n'
    monkeypatch.setattr(helper, 'POLICY_SHA', helper.digest(bodies[helper.FILES[0]]))
    monkeypatch.setattr(helper, 'RUNTIME_SHA', helper.digest(helper.canonical(helper.normalize_release(runtime, release))))
    return bodies, release


def parsed(helper, bodies):
    return [yaml.safe_load(bodies[n]) for n in helper.FILES]


def test_exact_admitted_scope_preserves_credentials_models_limits_and_https(helper, baseline):
    bodies, release = baseline
    original_policy, original_registry, original_runtime = parsed(helper, bodies)
    output, plan = helper.transform(bodies, release)
    policy, registry, runtime = parsed(helper, output)
    assert len(plan['admitted_workspaces']) == 41
    assert len(plan['protected_workspaces']) == 5
    assert helper.HTTPS not in output
    assert plan['before'][helper.HTTPS] == helper.digest(bodies[helper.HTTPS])
    for name in original_registry['workspaces']:
        if name in helper.PROTECTED:
            assert registry['workspaces'][name] == original_registry['workspaces'][name]
            assert policy['workspaces'][name] == original_policy['workspaces'][name]
        else:
            assert registry['workspaces'][name]['allow_execute'] is True
            assert registry['workspaces'][name]['allow_agent_dispatch'] is True
            assert 'dispatch' in policy['workspaces'][name]['operations']
    expected_runtime = copy.deepcopy(original_runtime)
    expected_runtime['allowed_workspace_roots'] = runtime['allowed_workspace_roots']
    assert runtime == expected_runtime
    old_paths = {r['path']: r['writable'] for r in original_runtime['allowed_workspace_roots']}
    new_paths = {r['path']: r['writable'] for r in runtime['allowed_workspace_roots']}
    assert all(new_paths[p] is False for p in set(new_paths) - set(old_paths))
    assert new_paths[helper.EXPECTED_ROOTS['shiny']] is False
    assert new_paths[helper.EXPECTED_ROOTS['obsidian']] is True  # internal access unchanged
    assert runtime['workers'] == original_runtime['workers']
    assert registry['unrelated'] == 'keep'


@pytest.mark.parametrize('mutation', ['extra', 'missing', 'path', 'traversal', 'bool', 'row'])
def test_malformed_registry_refused(helper, baseline, mutation):
    bodies, release = baseline
    registry = yaml.safe_load(bodies[helper.FILES[1]])
    if mutation == 'extra':
        registry['workspaces']['unexpected'] = {'path': '/etc'}
    elif mutation == 'missing':
        del registry['workspaces']['Qman']
    elif mutation == 'path':
        registry['workspaces']['Qman']['path'] = '/etc'
    elif mutation == 'traversal':
        registry['workspaces']['Qman']['path'] = '/home/operator/repos/Qman/../Qman'
    elif mutation == 'bool':
        registry['workspaces']['Qman']['allow_execute'] = 'true'
    else:
        registry['workspaces']['Qman'] = '/etc'
    bodies[helper.FILES[1]] = yaml.safe_dump(registry).encode()
    with pytest.raises(RuntimeError):
        helper.transform(bodies, release)


def test_symlink_roots_refused(helper, baseline, monkeypatch):
    bodies, release = baseline
    monkeypatch.setattr(helper.os.path, 'realpath', lambda p: '/elsewhere')
    with pytest.raises(RuntimeError, match='Symlink'):
        helper.transform(bodies, release)


@pytest.mark.parametrize('field,value', [('model', 'paid-model'), ('egress_policy', 'unrestricted'), ('root', '/etc')])
def test_runtime_drift_refused(helper, baseline, field, value):
    bodies, release = baseline
    runtime = yaml.safe_load(bodies[helper.FILES[2]])
    if field == 'model':
        runtime['workers']['wei']['model'] = value
    elif field == 'root':
        runtime['allowed_workspace_roots'][0]['path'] = value
    else:
        runtime[field] = value
    bodies[helper.FILES[2]] = yaml.safe_dump(runtime).encode()
    with pytest.raises(RuntimeError, match='frozen v19'):
        helper.transform(bodies, release)


def test_only_current_release_pointer_relocation_allowed(helper, baseline):
    bodies, release = baseline
    next_release = release.with_name('20261022T010000.000020Z')
    bodies[helper.FILES[2]] = bodies[helper.FILES[2]].replace(str(release).encode(), str(next_release).encode())
    helper.transform(bodies, next_release)
    with pytest.raises(RuntimeError, match='frozen v19'):
        helper.transform(bodies, release)


def test_policy_baseline_drift_and_duplicate_yaml_refused(helper, baseline):
    bodies, release = baseline
    changed = dict(bodies)
    changed[helper.FILES[0]] += b'\n'
    with pytest.raises(RuntimeError, match='baseline'):
        helper.transform(changed, release)
    bodies[helper.FILES[1]] += b'workspaces: {}\n'
    with pytest.raises(RuntimeError, match='Duplicate'):
        helper.transform(bodies, release)


@pytest.mark.parametrize('protected', ['obsidian', 'repos', 'AgentPorter'])
def test_protected_dispatch_refused_even_if_baseline_repin_attempted(helper, baseline, monkeypatch, protected):
    bodies, release = baseline
    policy = yaml.safe_load(bodies[helper.FILES[0]])
    policy['workspaces'][protected]['operations'].append('dispatch')
    bodies[helper.FILES[0]] = yaml.safe_dump(policy).encode()
    monkeypatch.setattr(helper, 'POLICY_SHA', helper.digest(bodies[helper.FILES[0]]))
    with pytest.raises(RuntimeError, match='Protected'):
        helper.transform(bodies, release)


def setup_private(helper, tmp_path, bodies):
    tmp_path.chmod(0o700)
    for name, body in bodies.items():
        p = tmp_path / name
        p.write_bytes(body)
        p.chmod(0o600)
    return helper.open_directory(tmp_path, os.getuid())


def test_apply_requires_reviewed_plan_and_preserves_durable_backup(helper, baseline, tmp_path):
    bodies, release = baseline
    output, plan = helper.transform(bodies, release)
    fd = setup_private(helper, tmp_path, bodies)
    expected = helper.digest(helper.canonical(plan))
    try:
        with pytest.raises(RuntimeError, match='SHA'):
            helper.apply(fd, os.getuid(), bodies, output, plan, '0' * 64)
        helper.apply(fd, os.getuid(), bodies, output, plan, expected)
        recovery = tmp_path / helper.RECOVERY
        assert stat.S_IMODE(recovery.stat().st_mode) == 0o700
        for name in helper.FILES:
            assert (tmp_path / name).read_bytes() == output[name]
            assert (recovery / name).read_bytes() == bodies[name]
            assert stat.S_IMODE((recovery / name).stat().st_mode) == 0o600
        assert json.loads((recovery / 'receipt.json').read_text())['state'] == 'applied'
        recovery_fd = helper.open_directory(recovery, os.getuid())
        try:
            helper.rollback(fd, recovery_fd, os.getuid(), expected)
            helper.rollback(fd, recovery_fd, os.getuid(), expected)  # idempotent
        finally:
            os.close(recovery_fd)
        assert all((tmp_path / n).read_bytes() == bodies[n] for n in bodies)
    finally:
        os.close(fd)


def test_midwrite_failure_rolls_back_all_prior_files(helper, baseline, tmp_path, monkeypatch):
    bodies, release = baseline
    output, plan = helper.transform(bodies, release)
    fd = setup_private(helper, tmp_path, bodies)
    original_write = helper.write
    def fail_second(fd_arg, name, body, exclusive=False):
        if fd_arg == fd and name == helper.FILES[1] and body == output[name]:
            raise OSError('synthetic publication failure')
        return original_write(fd_arg, name, body, exclusive)
    monkeypatch.setattr(helper, 'write', fail_second)
    try:
        with pytest.raises(OSError, match='synthetic'):
            helper.apply(fd, os.getuid(), bodies, output, plan, helper.digest(helper.canonical(plan)))
        assert all((tmp_path / n).read_bytes() == bodies[n] for n in bodies)
        assert json.loads((tmp_path / helper.RECOVERY / 'receipt.json').read_text())['state'] == 'rolled_back'
    finally:
        os.close(fd)


def test_crash_partial_commit_can_recover_but_newer_state_is_protected(helper, baseline, tmp_path):
    bodies, release = baseline
    output, plan = helper.transform(bodies, release)
    fd = setup_private(helper, tmp_path, bodies)
    expected = helper.digest(helper.canonical(plan))
    helper.apply(fd, os.getuid(), bodies, output, plan, expected)
    recovery_fd = helper.open_directory(tmp_path / helper.RECOVERY, os.getuid())
    try:
        helper.write(fd, helper.FILES[0], bodies[helper.FILES[0]])  # partial crash state
        helper.write(fd, helper.FILES[1], b'new unrelated state\n')
        with pytest.raises(RuntimeError, match='Newer state'):
            helper.rollback(fd, recovery_fd, os.getuid(), expected)
        assert (tmp_path / helper.FILES[2]).read_bytes() == output[helper.FILES[2]]
        helper.write(fd, helper.FILES[1], output[helper.FILES[1]])
        helper.rollback(fd, recovery_fd, os.getuid(), expected)
        assert all((tmp_path / n).read_bytes() == bodies[n] for n in bodies)
    finally:
        os.close(recovery_fd)
        os.close(fd)


@pytest.mark.parametrize('kind', ['symlink', 'mode', 'hardlink'])
def test_private_file_symlink_permission_hardlink_refused(helper, tmp_path, kind):
    p = tmp_path / 'file'
    p.write_bytes(b'synthetic')
    p.chmod(0o600)
    if kind == 'symlink':
        p.rename(tmp_path / 'target')
        p.symlink_to(tmp_path / 'target')
    elif kind == 'mode':
        p.chmod(0o640)
    else:
        os.link(p, tmp_path / 'second')
    fd = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        with pytest.raises((RuntimeError, OSError)):
            helper.private_read(fd, 'file', os.getuid())
    finally:
        os.close(fd)


def test_active_service_refused_before_sqlite_access(helper, monkeypatch):
    class Running:
        returncode = 0
        stdout = 'active\n'
    monkeypatch.setattr(helper.subprocess, 'run', lambda *a, **k: Running())
    with pytest.raises(RuntimeError, match='Stop A7Dev'):
        helper.quiet_and_stopped()


def test_https_scope_cannot_expand_even_with_policy_hash_repin(helper, baseline, monkeypatch):
    bodies, release = baseline
    policy = yaml.safe_load(bodies[helper.FILES[0]])
    policy['workspaces']['Qman']['operations'].append('https')
    bodies[helper.FILES[0]] = yaml.safe_dump(policy).encode()
    monkeypatch.setattr(helper, 'POLICY_SHA', helper.digest(bodies[helper.FILES[0]]))
    with pytest.raises(RuntimeError, match='HTTPS scope'):
        helper.transform(bodies, release)


def test_rollback_refuses_changed_https_and_corrupt_backup(helper, baseline, tmp_path):
    bodies, release = baseline
    output, plan = helper.transform(bodies, release)
    fd = setup_private(helper, tmp_path, bodies)
    expected = helper.digest(helper.canonical(plan))
    helper.apply(fd, os.getuid(), bodies, output, plan, expected)
    recovery_fd = helper.open_directory(tmp_path / helper.RECOVERY, os.getuid())
    try:
        helper.write(fd, helper.HTTPS, b'changed HTTPS')
        with pytest.raises(RuntimeError, match='HTTPS changed'):
            helper.rollback(fd, recovery_fd, os.getuid(), expected)
        helper.write(fd, helper.HTTPS, bodies[helper.HTTPS])
        helper.write(recovery_fd, helper.FILES[0], b'corrupt backup')
        with pytest.raises(RuntimeError, match='corrupt backup'):
            helper.rollback(fd, recovery_fd, os.getuid(), expected)
        assert (tmp_path / helper.FILES[1]).read_bytes() == output[helper.FILES[1]]
    finally:
        os.close(recovery_fd)
        os.close(fd)


@pytest.mark.parametrize('running_jobs,admissions', [(1, 0), (0, 1), (0, 0)])
def test_quiet_job_and_admission_checks(helper, tmp_path, monkeypatch, running_jobs, admissions):
    import sqlite3
    connection = sqlite3.connect(tmp_path / 'jobs.db')
    connection.execute('CREATE TABLE jobs(status TEXT)')
    connection.execute('CREATE TABLE job_admissions(id TEXT)')
    for _ in range(running_jobs):
        connection.execute('INSERT INTO jobs VALUES(?)', ('running',))
    for _ in range(admissions):
        connection.execute('INSERT INTO job_admissions VALUES(?)', ('synthetic',))
    connection.commit()
    connection.close()
    class Stopped:
        returncode = 3
        stdout = 'inactive\n'
    monkeypatch.setattr(helper.subprocess, 'run', lambda *a, **k: Stopped())
    monkeypatch.setattr(helper, 'STATE', tmp_path)
    monkeypatch.setattr(helper.Path, 'exists', lambda self: False)
    if running_jobs or admissions:
        with pytest.raises(RuntimeError, match='jobs|admissions'):
            helper.quiet_and_stopped()
    else:
        helper.quiet_and_stopped()


def test_missing_or_inaccessible_workspace_directory_refused(helper, baseline, monkeypatch):
    bodies, release = baseline
    monkeypatch.setattr(helper.Path, 'is_dir', lambda p: False)
    with pytest.raises(RuntimeError, match='Missing/inaccessible'):
        helper.transform(bodies, release)
