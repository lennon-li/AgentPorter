"""Offline ACL repair boundaries; live service acceptance is a separate gate.

Mutation fixtures use ordinary temporary directories. Only the reported UID is
mapped to the service UID, so real ACL syscalls can run without chown or sudo.
"""
import importlib.util
import json
import os
from pathlib import Path

import pytest

from tests.security.test_shared_directory_defaults import setup


@pytest.fixture
def access():
    source = Path(__file__).parents[2] / 'scripts/repair-a7dev-service-directory-access.py'
    spec = importlib.util.spec_from_file_location('service_directory_access_tests', source)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize('mode', [0o700, 0o750, 0o770, 0o755])
def test_target_grants_human_access_without_changing_other_rights(access, setup, mode):
    d, *_ = setup
    raw, after_mode = access.target_access(d, None, mode, 65534)
    after = d.decode_acl(raw)
    assert after[d.USER, 65534] == after[d.MASK, d.UNDEF] == 7
    assert after[d.UOBJ, d.UNDEF] == (mode >> 6) & 7
    assert after[d.GOBJ, d.UNDEF] == (mode >> 3) & 7
    assert after[d.OTHER, d.UNDEF] == mode & 7
    assert after_mode == (mode & ~0o070) | 0o070


@pytest.mark.parametrize('mask', range(8))
def test_preexisting_effective_rights_do_not_expand(access, setup, mask):
    d, *_ = setup
    entries = {(d.UOBJ, d.UNDEF): 7, (d.GOBJ, d.UNDEF): 7,
        (d.OTHER, d.UNDEF): 0, (d.USER, 12345): 7,
        (d.GROUP, 12346): 5, (d.MASK, d.UNDEF): mask}
    original = d.encode_acl(entries)
    raw, _ = access.target_access(d, original, 0o700 | (mask << 3), 65534)
    after = d.decode_acl(raw)
    for key in [(d.GOBJ, d.UNDEF), (d.USER, 12345), (d.GROUP, 12346)]:
        assert after[key] & after[d.MASK, d.UNDEF] == entries[key] & mask
    assert after[d.OTHER, d.UNDEF] == 0
    assert after[d.USER, 65534] == 7
    assert original == d.encode_acl(entries)


def test_plan_prunes_private_files_and_symlinks(access, setup):
    d, storage, inputs, root, _ = setup
    for name in ['.git', '.aws', '.venv', '.codex', 'node_modules']:
        (root / name).mkdir()
        (root / name / 'private').mkdir()
    (root / 'linked').symlink_to(root / 'docs', target_is_directory=True)
    file = root / 'research.txt'; file.write_bytes(b'unchanged')
    before = (file.stat(), file.read_bytes())
    result = access.plan(d, storage, inputs, ['agentporter-dev'],
        human_uid=65534, service_uid=os.getuid())
    assert {row['relative'] for row in result['records']} == {'.', 'docs'}
    assert result['skipped']['private_or_cache'] == 5
    assert result['skipped']['symlink'] == 1
    assert (file.stat(), file.read_bytes()) == before


def test_wrong_plan_hash_cannot_create_recovery_or_modify_acl(access, setup):
    d, storage, inputs, root, state = setup
    fd = d.open_root(root)
    try:
        before = d.xattr(fd, d.ACCESS)
    finally:
        os.close(fd)
    fd = os.open(state, os.O_RDONLY | os.O_DIRECTORY)
    try:
        with pytest.raises(RuntimeError, match='plan changed'):
            access.apply(d, storage, inputs, ['agentporter-dev'], '0' * 64, fd,
                human_uid=65534, service_uid=os.getuid())
    finally:
        os.close(fd)
    assert not list(state.iterdir())
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
    try:
        assert d.xattr(fd, d.ACCESS) == before
    finally:
        os.close(fd)


@pytest.fixture
def mutation(access, setup, monkeypatch):
    d, _, _, root, state = setup
    (root / 'docs' / 'research.txt').write_bytes(b'unchanged')
    identity = d.identity
    monkeypatch.setattr(d, 'identity', lambda fd: {**identity(fd), 'uid': 994})
    originals = {}
    records = []
    for relative in ['docs', '.']:
        path = root / relative
        path.chmod(0o700)
        os.setxattr(path, d.DEFAULT, d.encode_acl({
            (d.UOBJ, d.UNDEF): 7, (d.GOBJ, d.UNDEF): 0, (d.OTHER, d.UNDEF): 0}))
        fd = d.open_root(path)
        try:
            before = d.identity(fd)
            default = d.xattr(fd, d.DEFAULT)
            raw, mode = access.target_access(d, d.unb64(before['access']), before['mode'], 65534)
            records.append(dict(workspace='agentporter-dev', relative=relative,
                before=before, default=d.b64(default), access_after=d.b64(raw), mode_after=mode))
            originals[relative] = (before['mode'], before['access'], default)
        finally:
            os.close(fd)
    document = {'plan': {'roots': {'agentporter-dev': records[-1]['before']}, 'records': records},
        'phase': 'prepared'}
    return access, d, root, state, records, document, originals


def run_mutation(fixture, rollback=False):
    a, d, root, state, _, document, _ = fixture
    fd = d.open_root(state)
    try:
        a.mutate(d, {'agentporter-dev': str(root)}, document, fd, rollback=rollback)
    finally:
        os.close(fd)


def test_real_acl_apply_and_rollback_preserve_defaults_and_files(mutation):
    _, d, root, state, records, document, originals = mutation
    file = root / 'docs' / 'research.txt'
    before = file.stat(), file.read_bytes()
    run_mutation(mutation)
    assert document['phase'] == 'applied' and document['completed_directories'] == 2
    for row in records:
        fd = d.open_root(root / row['relative'])
        try:
            assert d.identity(fd)['access'] == row['access_after']
            assert d.xattr(fd, d.DEFAULT) == d.unb64(row['default'])
        finally:
            os.close(fd)
    run_mutation(mutation, rollback=True)
    assert document['phase'] == 'rolled_back'
    for relative, (mode, raw, default) in originals.items():
        fd = d.open_root(root / relative)
        try:
            after = d.identity(fd)
            assert (after['mode'], after['access'], d.xattr(fd, d.DEFAULT)) == (mode, raw, default)
        finally:
            os.close(fd)
    assert (file.stat(), file.read_bytes()) == before
    assert json.loads((state / 'journal.json').read_text())['phase'] == 'rolled_back'


def test_changed_acl_aborts_before_any_mutation(mutation):
    _, d, root, state, records, _, _ = mutation
    (root / 'docs').chmod(0o750)
    with pytest.raises(RuntimeError, match='changed since plan'):
        run_mutation(mutation)
    fd = d.open_root(root)
    try:
        assert d.identity(fd)['access'] == records[-1]['before']['access']
    finally:
        os.close(fd)
    assert not list(state.iterdir())


@pytest.mark.parametrize('field,value', [('uid', 1000), ('gid', 12345), ('ino', 0),
    ('mount_id', 'different'), ('access', 'changed'), ('ctime_ns', 0)])
def test_identity_or_metadata_change_is_rejected(mutation, monkeypatch, field, value):
    a, d, root, _, records, _, _ = mutation
    identity = d.identity
    monkeypatch.setattr(d, 'identity', lambda fd: {**identity(fd), field: value})
    fd = d.open_root(root / 'docs')
    try:
        with pytest.raises(RuntimeError, match='changed'):
            a.current_allowed(d, fd, records[0])
    finally:
        os.close(fd)


def test_default_acl_change_is_rejected(mutation):
    a, d, root, _, records, _, _ = mutation
    os.setxattr(root / 'docs', d.DEFAULT, d.encode_acl({
        (d.UOBJ, d.UNDEF): 7, (d.GOBJ, d.UNDEF): 5, (d.OTHER, d.UNDEF): 0}))
    fd = d.open_root(root / 'docs')
    try:
        with pytest.raises(RuntimeError, match='default ACL changed'):
            a.current_allowed(d, fd, records[0])
    finally:
        os.close(fd)


def test_partial_failure_is_journaled_and_can_be_rolled_back(mutation, monkeypatch):
    a, d, root, state, _, document, originals = mutation
    setxattr = a.os.setxattr
    count = 0
    def fail_second(fd, key, value):
        nonlocal count
        count += 1
        if count == 2:
            raise OSError('synthetic ACL failure')
        return setxattr(fd, key, value)
    monkeypatch.setattr(a.os, 'setxattr', fail_second)
    with pytest.raises(OSError, match='synthetic'):
        run_mutation(mutation)
    journal = json.loads((state / 'journal.json').read_text())
    assert journal['phase'] == 'applying' and journal['completed_directories'] == 1
    monkeypatch.setattr(a.os, 'setxattr', setxattr)
    run_mutation(mutation, rollback=True)
    assert document['phase'] == 'rolled_back'
    for relative, (mode, raw, default) in originals.items():
        fd = d.open_root(root / relative)
        try:
            assert (d.identity(fd)['mode'], d.identity(fd)['access'], d.xattr(fd, d.DEFAULT)) == (mode, raw, default)
        finally:
            os.close(fd)
