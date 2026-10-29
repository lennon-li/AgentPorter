"""Synthetic retry recovery evidence; no service/private installation reads."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import stat

import pytest
import yaml


ROOT = Path(__file__).resolve().parents[2]


def load_source(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


@pytest.fixture
def fixture(tmp_path, monkeypatch):
    script = load_source('retry_preflight', ROOT / 'scripts/preflight-a7dev-project-access-retry.py')
    helper = load_source('retry_authorization', ROOT / 'scripts/authorize-a7dev-project-delegation.py')
    config = tmp_path / 'config'
    config.mkdir(mode=0o700)
    recovery = config / helper.RECOVERY
    recovery.mkdir(mode=0o700)
    current = tmp_path / 'current'
    current.symlink_to(script.OLD_RELEASE)
    helper.CONFIG = config
    helper.CURRENT = current
    runtime = {'allowed_workspace_roots': [{'path': '/synthetic/project', 'writable': True}],
               'workers': {'wei': {'model': 'opencode/glm-5.3-flash-free',
                                   'executable': str(script.OLD_RELEASE / 'cli/wei/opencode.exe')}},
               'egress_policy': 'provider_origin'}
    helper.RUNTIME_SHA = helper.digest(helper.canonical(helper.normalize_release(runtime, script.OLD_RELEASE)))
    old_runtime = yaml.safe_dump(runtime).encode()
    new_runtime = old_runtime.replace(str(script.OLD_RELEASE).encode(), str(script.NEW_RELEASE).encode())
    bodies = {'development-runtime.yaml': old_runtime,
              'public-client-policy.yaml': b'synthetic restored policy\n',
              'workspaces.yaml': b'synthetic registry\n',
              'public-https.yaml': b'synthetic unchanged https\n'}
    before = {name: helper.digest(new_runtime if name == 'development-runtime.yaml' else body)
              for name, body in bodies.items()}
    after = {name: helper.digest(b'after ' + bodies[name]) for name in helper.FILES}
    plan = {'version': 1, 'release': str(script.NEW_RELEASE), 'before': before, 'after': after,
            'admitted_workspaces': sorted(set(helper.EXPECTED_ROOTS) - helper.PROTECTED),
            'protected_workspaces': sorted(helper.PROTECTED), 'https_workspaces': ['cranary'],
            'generic_shell_network': False, 'production_changed': False}
    receipt = {'state': 'rolled_back', 'plan': plan}
    for name, body in bodies.items():
        (config / name).write_bytes(body)
        (config / name).chmod(0o600)
    for name in helper.FILES:
        (recovery / name).write_bytes(new_runtime if name == 'development-runtime.yaml' else bodies[name])
        (recovery / name).chmod(0o600)
    (recovery / 'receipt.json').write_bytes(helper.canonical(receipt))
    (recovery / 'receipt.json').chmod(0o600)
    monkeypatch.setattr(script, 'BEFORE', before)
    monkeypatch.setattr(script, 'AFTER', after)
    monkeypatch.setattr(script, 'PLAN_SHA', helper.digest(helper.canonical(plan)))
    config_fd = helper.open_directory(config, os.getuid())
    recovery_fd = helper.open_directory(recovery, os.getuid())
    result = {'script': script, 'helper': helper, 'config': config, 'recovery': recovery,
              'config_fd': config_fd, 'recovery_fd': recovery_fd, 'receipt': receipt,
              'uid': os.getuid(), 'bodies': bodies, 'current': current}
    yield result
    os.close(recovery_fd)
    os.close(config_fd)


def validate(data):
    return data['script'].validate(data['helper'], data['config_fd'], data['recovery_fd'], data['uid'])


def write_receipt(data, receipt):
    (data['recovery'] / 'receipt.json').write_bytes(data['helper'].canonical(receipt))


def test_normalized_old_runtime_accepted_with_new_runtime_rollback_backup(fixture):
    result = validate(fixture)
    assert result['passed'] is True
    assert result['admitted_projects'] == 41
    assert result['protected_projects'] == 5
    assert result['policy_changed'] is False
    assert (fixture['config'] / 'development-runtime.yaml').read_bytes() != (
        fixture['recovery'] / 'development-runtime.yaml').read_bytes()
    assert fixture['recovery'].is_dir()


@pytest.mark.parametrize('mutation', ['policy', 'registry', 'https', 'runtime', 'model', 'release'])
def test_stale_or_newer_configuration_refused(fixture, mutation):
    if mutation in ('policy', 'registry', 'https'):
        name = {'policy': 'public-client-policy.yaml', 'registry': 'workspaces.yaml', 'https': 'public-https.yaml'}[mutation]
        (fixture['config'] / name).write_bytes(b'newer state')
    elif mutation == 'runtime':
        p = fixture['config'] / 'development-runtime.yaml'
        p.write_bytes(p.read_bytes().replace(b'provider_origin', b'unrestricted'))
    elif mutation == 'model':
        p = fixture['config'] / 'development-runtime.yaml'
        p.write_bytes(p.read_bytes().replace(b'glm-5.3-flash-free', b'paid-model'))
    else:
        fixture['current'].unlink()
        fixture['current'].symlink_to(fixture['script'].NEW_RELEASE)
    with pytest.raises(RuntimeError, match='changed'):
        validate(fixture)
    assert fixture['recovery'].is_dir()


@pytest.mark.parametrize('mutation', ['hash', 'state', 'backup', 'scope', 'network'])
def test_invalid_receipt_or_corrupt_backup_refused(fixture, mutation):
    receipt = copy.deepcopy(fixture['receipt'])
    if mutation == 'hash':
        receipt['plan']['extra'] = 'unexpected'
    elif mutation == 'state':
        receipt['state'] = 'applied'
    elif mutation == 'backup':
        (fixture['recovery'] / 'development-runtime.yaml').write_bytes(b'corrupt backup')
    elif mutation == 'scope':
        receipt['plan']['admitted_workspaces'].append('repos')
    else:
        receipt['plan']['generic_shell_network'] = True
    write_receipt(fixture, receipt)
    with pytest.raises(RuntimeError):
        validate(fixture)


def test_preserve_requires_quiet_stopped_service_before_any_mutation(fixture, monkeypatch):
    def running():
        raise RuntimeError('Service still active')
    monkeypatch.setattr(fixture['helper'], 'quiet_and_stopped', running)
    with pytest.raises(RuntimeError, match='active'):
        fixture['script'].preserve(fixture['helper'], fixture['config_fd'], fixture['recovery_fd'], fixture['uid'])
    assert fixture['recovery'].is_dir()
    assert not list(fixture['config'].glob('project-delegation-retry-archive-*'))


def test_preserve_durably_moves_all_evidence_without_changing_config(fixture, monkeypatch):
    monkeypatch.setattr(fixture['helper'], 'quiet_and_stopped', lambda: None)
    before = {p.name: p.read_bytes() for p in fixture['recovery'].iterdir()}
    result = fixture['script'].preserve(fixture['helper'], fixture['config_fd'], fixture['recovery_fd'], fixture['uid'])
    archived = Path(result['archive'])
    assert archived.name == 'previous'
    assert stat.S_IMODE(archived.parent.stat().st_mode) == 0o700
    assert not fixture['recovery'].exists()
    assert {p.name: p.read_bytes() for p in archived.iterdir()} == before
    assert all((fixture['config'] / n).read_bytes() == b for n, b in fixture['bodies'].items())


def test_existing_archive_never_overwritten(fixture, monkeypatch):
    monkeypatch.setattr(fixture['helper'], 'quiet_and_stopped', lambda: None)
    monkeypatch.setattr(fixture['script'].secrets, 'token_hex', lambda n: 'existing')
    archive = fixture['config'] / 'project-delegation-retry-archive-existing'
    archive.mkdir(mode=0o700)
    previous = archive / 'previous'
    previous.mkdir(mode=0o700)
    (previous / 'old-evidence').write_bytes(b'preserve me')
    with pytest.raises(FileExistsError):
        fixture['script'].preserve(fixture['helper'], fixture['config_fd'], fixture['recovery_fd'], fixture['uid'])
    assert (previous / 'old-evidence').read_bytes() == b'preserve me'
    assert fixture['recovery'].is_dir()


def test_atomic_rename_refuses_even_existing_empty_destination(fixture):
    archive = fixture['config'] / 'archive'
    archive.mkdir(mode=0o700)
    (archive / 'previous').mkdir(mode=0o700)
    fd = os.open(archive, os.O_RDONLY | os.O_DIRECTORY)
    try:
        with pytest.raises(FileExistsError):
            fixture['script'].rename_noreplace(fixture['config_fd'], fixture['helper'].RECOVERY, fd, 'previous')
        assert fixture['recovery'].is_dir()
    finally:
        os.close(fd)


def test_retry_preflight_loads_only_hash_pinned_immutable_helper(fixture, tmp_path, monkeypatch):
    path = tmp_path / 'helper.py'
    path.write_text('loaded = True\n')
    path.chmod(0o444)
    script = fixture['script']
    monkeypatch.setattr(script, 'HELPER', path)
    monkeypatch.setattr(script, 'HELPER_SHA', fixture['helper'].digest(path.read_bytes()))
    assert script.load_helper().loaded is True
    path.chmod(0o644)
    with pytest.raises(RuntimeError, match='immutable'):
        script.load_helper()
    path.chmod(0o444)
    monkeypatch.setattr(script, 'HELPER_SHA', '0' * 64)
    with pytest.raises(RuntimeError, match='hash'):
        script.load_helper()
