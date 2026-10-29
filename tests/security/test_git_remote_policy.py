"""Fixed remote authority must not follow caller-selected origins or roots."""
import copy
import json
from pathlib import Path
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from agentporter.git_approvals import GitApprovalVerifier
from agentporter.git_remote_policy import load_owner_git_remotes


class Registry:
    def __init__(self, root):
        self.entries = {'repo': SimpleNamespace(path=str(root), writable=True, allow_git=True)}
    def get(self, name):
        return self.entries[name]
    def list_all(self):
        return [{'path': entry.path} for entry in self.entries.values()]


def fixture(tmp_path):
    root = tmp_path / 'repo'
    root.mkdir()
    config = tmp_path / 'owner'
    config.mkdir(mode=0o700)
    state = tmp_path / 'state'
    state.mkdir(mode=0o700)
    key = Ed25519PrivateKey.generate().public_key()
    ledger = config / 'ledger.sqlite'
    GitApprovalVerifier(key, ledger)
    data = {'version': 1, 'verification_key': key.public_bytes(Encoding.Raw, PublicFormat.Raw).hex(),
        'ledger_path': str(ledger), 'grants': [
            {'workspace_id': 'repo', 'remote_id': 'origin', 'url': 'https://example.com/owner/repo.git',
             'ref': 'refs/heads/feature', 'operations': ['push', 'fetch'],
             'credential_file': str(config / 'token'), 'username': 'x-access-token'}]}
    registry = Registry(root)
    return config, state, registry, data


def write(config, data):
    path = config / 'git-remote-policy.json'
    path.write_text(json.dumps(data))
    path.chmod(0o600)
    return path


def test_absent_policy_is_disabled_without_creating_authority(tmp_path):
    assert load_owner_git_remotes(tmp_path / 'absent', None, None) is None
    assert not (tmp_path / 'absent').exists()


def test_fixed_authority_loads_without_token_read_or_network(tmp_path):
    config, state, registry, data = fixture(tmp_path)
    write(config, data)
    authority = load_owner_git_remotes(config, registry, state)
    grant, broker = authority.authorize('repo', 'origin', 'refs/heads/feature', 'push')
    assert grant.repository.url == data['grants'][0]['url']
    assert broker.remote == grant.repository
    assert not (config / 'token').exists()
    assert grant.operations == frozenset({'fetch', 'push'})


@pytest.mark.parametrize('args', [
    ('other', 'origin', 'refs/heads/feature', 'push'),
    ('repo', 'evil', 'refs/heads/feature', 'push'),
    ('repo', 'origin', 'refs/heads/main', 'push'),
    ('repo', 'origin', 'refs/heads/feature', 'pull'),
])
def test_caller_cannot_expand_exact_authority(tmp_path, args):
    config, state, registry, data = fixture(tmp_path)
    write(config, data)
    authority = load_owner_git_remotes(config, registry, state)
    with pytest.raises(PermissionError, match='outside owner'):
        authority.authorize(*args)


@pytest.mark.parametrize('change', ['policy', 'removed_policy', 'replacement_root', 'permissions', 'catalog'])
def test_authority_is_revalidated_at_use(tmp_path, change):
    config, state, registry, data = fixture(tmp_path)
    path = write(config, data)
    authority = load_owner_git_remotes(config, registry, state)
    if change == 'policy':
        path.write_text(path.read_text() + '\n')
    elif change == 'removed_policy':
        path.unlink()
    elif change == 'replacement_root':
        root = Path(registry.get('repo').path)
        root.rename(root.with_name('previous'))
        root.mkdir()
    elif change == 'permissions':
        registry.get('repo').writable = False
    elif change == 'catalog':
        registry.entries['exposes_authority'] = SimpleNamespace(path=str(tmp_path))
    with pytest.raises(PermissionError):
        authority.authorize('repo', 'origin', 'refs/heads/feature', 'push')


@pytest.mark.parametrize('field,value', [
    ('url', 'http://example.com/owner/repo.git'),
    ('url', 'https://token@example.com/owner/repo.git'),
    ('ref', 'refs/tags/release'), ('ref', 'refs/heads/*'),
    ('operations', ['push', 'force']), ('operations', ['push', 'push']),
    ('operations', []), ('operations', [True]),
    ('workspace_id', '*'), ('remote_id', '../origin'),
    ('credential_file', '/tmp/../secret'), ('credential_file', 'relative'),
    ('username', 'user:secret'),
])
def test_malformed_grants_fail_closed(tmp_path, field, value):
    config, state, registry, data = fixture(tmp_path)
    data['grants'][0][field] = value
    write(config, data)
    with pytest.raises(PermissionError):
        load_owner_git_remotes(config, registry, state)


@pytest.mark.parametrize('kind', ['duplicate', 'inconsistent', 'extra_field', 'extra_top', 'inside_root', 'readonly', 'missing_ledger'])
def test_invalid_authority_configuration_is_rejected(tmp_path, kind):
    config, state, registry, data = fixture(tmp_path)
    if kind in {'duplicate', 'inconsistent'}:
        second = copy.deepcopy(data['grants'][0])
        if kind == 'inconsistent':
            second['ref'] = 'refs/heads/second'
            second['url'] = 'https://example.com/other/repo.git'
        data['grants'].append(second)
    elif kind == 'extra_field':
        data['grants'][0]['force'] = True
    elif kind == 'extra_top':
        data['allow_all'] = True
    elif kind == 'inside_root':
        data['grants'][0]['credential_file'] = str(Path(registry.get('repo').path) / 'token')
    elif kind == 'readonly':
        registry.get('repo').writable = False
    elif kind == 'missing_ledger':
        Path(data['ledger_path']).unlink()
    write(config, data)
    with pytest.raises((PermissionError, FileNotFoundError)):
        load_owner_git_remotes(config, registry, state)
    if kind == 'missing_ledger':
        assert not Path(data['ledger_path']).exists()


@pytest.mark.parametrize('kind', ['public', 'symlink', 'hardlink', 'duplicates'])
def test_policy_file_must_be_protected_and_unambiguous(tmp_path, kind):
    config, state, registry, data = fixture(tmp_path)
    path = write(config, data)
    if kind == 'public':
        path.chmod(0o644)
    elif kind == 'symlink':
        target = path.with_name('other')
        path.rename(target)
        path.symlink_to(target)
    elif kind == 'hardlink':
        path.with_name('alias').hardlink_to(path)
    elif kind == 'duplicates':
        path.write_text(path.read_text().replace('"version": 1', '"version": 1, "version": 1'))
    with pytest.raises((PermissionError, OSError)):
        load_owner_git_remotes(config, registry, state)
