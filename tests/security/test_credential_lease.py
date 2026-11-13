"""Synthetic native token rotation, durable recovery and hostile filesystem tests."""
import json
import multiprocessing
import os
from pathlib import Path

import pytest

from agentporter.agents.credential_lease import CredentialLease
from tests.security.test_development_runtime import runtime_factory, no_probe, save


def auth(token='old', account='research'):
    return json.dumps({'auth_mode': 'chatgpt', 'tokens': {
        'account_id': account, 'access_token': token, 'refresh_token': token}}).encode()


@pytest.fixture
def paths(tmp_path):
    canonical = tmp_path / 'account'
    canonical.mkdir(mode=0o700)
    source = canonical / 'auth.json'
    source.write_bytes(auth())
    source.chmod(0o600)
    return source, tmp_path / 'worker/.codex/auth.json'


def test_rotation_is_reused_by_next_worker_and_survives_cleanup(paths):
    source, target = paths
    lease = CredentialLease(source, target)
    replacement = target.with_suffix('.new')
    replacement.write_bytes(auth('rotated'))
    replacement.chmod(0o600)
    replacement.replace(target)  # native clients commonly save by rename
    lease.finish()
    assert source.read_bytes() == auth('rotated')
    assert source.stat().st_mode & 0o777 == 0o600
    target.unlink()
    second = CredentialLease(source, target)
    assert target.read_bytes() == auth('rotated')
    second.finish()
    assert not list(source.parent.glob('*pending*'))


def _attempt(source, target, channel):
    try:
        lease = CredentialLease(Path(source), Path(target))
    except PermissionError as error:
        channel.send(str(error))
    else:
        lease.finish()
        channel.send('UNEXPECTED_SUCCESS')
    finally:
        channel.close()


def test_concurrent_process_cannot_renew_same_account(paths):
    source, target = paths
    first = CredentialLease(source, target)
    # spawn avoids inheriting the first process's lock descriptor.
    context = multiprocessing.get_context('spawn')
    parent, child = context.Pipe()
    process = context.Process(target=_attempt, args=(str(source), str(target.parent/'other.json'), child))
    process.start()
    try:
        assert parent.poll(10)
        assert 'active worker' in parent.recv()
        process.join(10)
        assert process.exitcode == 0
    finally:
        if process.is_alive():
            process.terminate()
            process.join()
        parent.close()
        child.close()
        first.finish()


def test_crash_recovery_blocks_restart_without_discarding_rotation(paths):
    source, target = paths
    first = CredentialLease(source, target)
    target.write_bytes(auth('rotated'))
    first.close()  # simulate a gateway crash before monitored cleanup
    with pytest.raises(PermissionError, match='pending owner recovery'):
        CredentialLease(source, target.parent / 'next.json')
    assert target.read_bytes() == auth('rotated')
    assert source.read_bytes() == auth()


def test_external_update_is_not_overwritten_when_worker_did_not_refresh(paths):
    source, target = paths
    lease = CredentialLease(source, target)
    source.write_bytes(auth('external'))
    lease.finish()
    assert source.read_bytes() == auth('external')


def test_conflict_retains_both_versions_and_blocks_reuse(paths):
    source, target = paths
    lease = CredentialLease(source, target)
    target.write_bytes(auth('worker'))
    source.write_bytes(auth('external'))
    with pytest.raises(PermissionError, match='conflict'):
        lease.finish()
    assert target.read_bytes() == auth('worker')
    assert source.read_bytes() == auth('external')
    with pytest.raises(PermissionError, match='pending owner recovery'):
        CredentialLease(source, target.parent / 'next.json')


@pytest.mark.parametrize('kind', ['symlink', 'hardlink', 'public', 'account', 'billing', 'duplicate', 'oversize'])
def test_unsafe_native_result_is_never_published(paths, tmp_path, kind):
    source, target = paths
    lease = CredentialLease(source, target)
    if kind in {'symlink', 'hardlink'}:
        unrelated = tmp_path / 'other'
        unrelated.write_bytes(auth('secret'))
        unrelated.chmod(0o600)
        target.unlink()
        if kind == 'symlink':
            target.symlink_to(unrelated)
        else:
            os.link(unrelated, target)
    elif kind == 'public':
        target.chmod(0o644)
    elif kind == 'account':
        target.write_bytes(auth('rotated', account='personal'))
    elif kind == 'billing':
        target.write_bytes(b'{"auth_mode":"apikey","OPENAI_API_KEY":"synthetic"}')
    elif kind == 'duplicate':
        target.write_bytes(b'{"tokens":{},"tokens":{}}')
    else:
        target.write_bytes(b'x' * (1024 * 1024 + 1))
    with pytest.raises((PermissionError, OSError)):
        lease.finish()
    assert source.read_bytes() == auth()
    assert target.exists()


def test_account_sources_remain_independent(paths, tmp_path):
    source, target = paths
    separate = tmp_path / 'personal'
    separate.mkdir(mode=0o700)
    other = separate / 'auth.json'
    other.write_bytes(auth(account='personal'))
    other.chmod(0o600)
    first = CredentialLease(source, target)
    second = CredentialLease(other, tmp_path / 'other-worker/auth.json')
    target.write_bytes(auth('rotated'))
    first.finish()
    second.finish()
    assert other.read_bytes() == auth(account='personal')


def test_source_parent_swap_cannot_redirect_publication(paths, tmp_path):
    source, target = paths
    lease = CredentialLease(source, target)
    target.write_bytes(auth('rotated'))
    saved = tmp_path / 'saved'
    source.parent.rename(saved)
    source.parent.mkdir(mode=0o700)
    source.write_bytes(auth('external'))
    source.chmod(0o600)
    with pytest.raises(PermissionError, match='directory moved'):
        lease.finish()
    assert source.read_bytes() == auth('external')
    assert (saved/'auth.json').read_bytes() == auth()


def test_runtime_cleanup_persists_refresh_before_deleting_home(runtime_factory, monkeypatch):
    runtime, config, _, workspace, _ = runtime_factory()
    no_probe(monkeypatch, runtime)
    source = Path(config['workers']['codex_impl']['credentials']['.codex/auth.json'])
    source.write_bytes(auth())
    launch = runtime.prepare('codex_impl', str(workspace), False, ['/usr/bin/python3', '--version'])
    home = Path(launch.command[launch.command.index('/home/worker') - 1])
    (home / '.codex/auth.json').write_bytes(auth('rotated'))
    launch.cleanup()
    assert source.read_bytes() == auth('rotated')
    assert not home.exists()


def test_runtime_cleanup_retains_home_on_conflict(runtime_factory, monkeypatch):
    runtime, config, _, workspace, _ = runtime_factory()
    no_probe(monkeypatch, runtime)
    source = Path(config['workers']['codex_impl']['credentials']['.codex/auth.json'])
    source.write_bytes(auth())
    launch = runtime.prepare('codex_impl', str(workspace), False, ['/usr/bin/python3', '--version'])
    home = Path(launch.command[launch.command.index('/home/worker') - 1])
    (home / '.codex/auth.json').write_bytes(auth('rotated'))
    source.write_bytes(auth('external'))
    with pytest.raises(PermissionError, match='conflict'):
        launch.cleanup()
    assert home.exists()
    assert (home / '.codex/auth.json').read_bytes() == auth('rotated')


def test_explicit_same_account_alias_uses_one_canonical_store(runtime_factory, monkeypatch):
    runtime, config, path, workspace, _ = runtime_factory()
    source = config['workers']['codex_impl']['credentials']['.codex/auth.json']
    config['credential_accounts'] = {'intended-account': {'auth_file': source}}
    for agent in ('codex_impl', 'codex_review'):
        config['workers'][agent]['credentials']['.codex/auth.json'] = source
        config['workers'][agent]['credential_account'] = 'intended-account'
    save(config, path)
    no_probe(monkeypatch, runtime)
    first = runtime.prepare('codex_impl', str(workspace), False, ['/usr/bin/python3', '--version'])
    try:
        with pytest.raises(PermissionError, match='active worker'):
            runtime.prepare('codex_review', str(workspace), False, ['/usr/bin/python3', '--version'])
    finally:
        first.cleanup()
    config['workers']['codex_review']['credential_account'] = 'different-account'
    save(config, path)
    with pytest.raises(PermissionError):
        runtime.prepare('codex_review', str(workspace), False, ['/usr/bin/python3', '--version'])
