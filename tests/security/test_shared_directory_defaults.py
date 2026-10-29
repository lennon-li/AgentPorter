"""Real default-xattr repair regressions with ordinary-user fixture ownership."""
import importlib.util
import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml


def test_open_root_traverses_execute_only_ancestors(setup, tmp_path):
    h, *_ = setup
    ancestor = tmp_path / 'traverse-only'; ancestor.mkdir()
    target = ancestor / 'workspace'; target.mkdir()
    (target / 'ordinary.txt').write_text('unchanged')
    ancestor.chmod(0o100)
    try:
        with pytest.raises(PermissionError):
            os.open(ancestor, os.O_RDONLY | os.O_DIRECTORY)
        fd = h.open_root(target)
        try:
            assert sorted(os.listdir(fd)) == ['ordinary.txt']
            assert os.fstat(fd).st_ino == target.stat().st_ino
        finally:
            os.close(fd)
    finally:
        ancestor.chmod(0o700)


def test_open_root_still_requires_read_access_to_final_root(setup, tmp_path):
    h, *_ = setup
    target = tmp_path / 'unreadable-root'; target.mkdir(); target.chmod(0o100)
    try:
        with pytest.raises(PermissionError):
            h.open_root(target)
    finally:
        target.chmod(0o700)


def test_open_root_rejects_ancestor_symlink_swapped_after_validation(setup, tmp_path, monkeypatch):
    h, *_ = setup
    ancestor = tmp_path / 'ancestor'; ancestor.mkdir()
    target = ancestor / 'workspace'; target.mkdir()
    outside = tmp_path / 'outside'; outside.mkdir()
    (outside / 'workspace').mkdir()
    original = os.path.realpath
    swapped = False
    def swap_after_resolving(path):
        nonlocal swapped
        resolved = original(path)
        if Path(path) == target and not swapped:
            ancestor.rename(tmp_path / 'original-ancestor')
            ancestor.symlink_to(outside, target_is_directory=True)
            swapped = True
        return resolved
    monkeypatch.setattr(h.os.path, 'realpath', swap_after_resolving)
    with pytest.raises(OSError):
        h.open_root(target)
    assert swapped


@pytest.fixture
def setup(tmp_path):
    source = Path(__file__).parents[2] / 'scripts/repair-a7dev-shared-directory-defaults.py'
    spec = importlib.util.spec_from_file_location('directory_defaults', source)
    helper = importlib.util.module_from_spec(spec); spec.loader.exec_module(helper)
    root = tmp_path / 'workspace'; root.mkdir()
    (root / 'docs').mkdir()
    storage = SimpleNamespace(EXPECTED_ROOTS={'agentporter-dev': str(root)}, PROTECTED={'protected'},
                              FILES=('policy', 'registry', 'runtime'))
    storage.UniqueLoader = yaml.SafeLoader
    values = ({'workspaces': {'agentporter-dev': {'path': str(root), 'operations': ['write', 'dispatch', 'dispatch_write']}}},
              {'workspaces': {'agentporter-dev': {'path': str(root), 'writable': True, 'allow_execute': True, 'allow_agent_dispatch': True}}},
              {'enabled': True, 'profile': 'development', 'allowed_workspace_roots': [{'path': str(root), 'writable': True}]})
    inputs = {name: yaml.safe_dump(value).encode() for name, value in zip(storage.FILES, values)}
    state = tmp_path / 'state'; state.mkdir(mode=0o700)
    return helper, storage, inputs, root, state


def prepare(setup):
    h, storage, inputs, root, state = setup
    value = h.plan(storage, inputs, ['agentporter-dev'], os.getuid(), 994)
    return value, h.digest(h.canonical(value))


def apply(setup, expected):
    h, storage, inputs, root, state = setup
    fd = os.open(state, os.O_RDONLY | os.O_DIRECTORY)
    try: return h.apply(storage, inputs, ['agentporter-dev'], expected, fd, os.getuid(), 994)
    finally: os.close(fd)


def rollback(setup, expected):
    h, storage, inputs, root, state = setup
    fd = os.open(state, os.O_RDONLY | os.O_DIRECTORY)
    try: h.rollback(storage, inputs, ['agentporter-dev'], expected, fd)
    finally: os.close(fd)


def read_default(h, path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try: return h.xattr(fd, h.DEFAULT)
    finally: os.close(fd)


def test_repair_only_defaults_and_backup_retained_on_rollback(setup):
    h, storage, inputs, root, state = setup
    before = {path: (path.stat().st_mode, path.stat().st_uid, path.stat().st_gid,
                     os.listxattr(path), read_default(h, path)) for path in (root, root / 'docs')}
    value, expected = prepare(setup)
    assert len(value['records']) == 2
    result = apply(setup, expected)
    recovery = state / result['recovery']
    original_backup = (recovery / 'plan.json').read_bytes()
    assert recovery.stat().st_mode & 0o777 == 0o700
    assert all(path.stat().st_mode & 0o777 == 0o600 for path in recovery.iterdir())
    for path, (mode, uid, gid, attrs, original) in before.items():
        assert (path.stat().st_mode, path.stat().st_uid, path.stat().st_gid) == (mode, uid, gid)
        entries = h.decode_acl(read_default(h, path))
        assert entries[h.USER, os.getuid()] == 7
        assert entries[h.USER, 994] == 0
    second, second_hash = prepare(setup)
    assert second['records'] == []
    assert apply(setup, second_hash)['already_compliant'] is True
    rollback(setup, expected)
    assert all(read_default(h, path) == original for path, (_, _, _, _, original) in before.items())
    assert (recovery / 'plan.json').read_bytes() == original_backup
    assert json.loads((recovery / 'journal.json').read_text())['phase'] == 'rolled_back'


def test_existing_masked_service_and_other_named_rights_do_not_expand(setup):
    h, _, _, root, _ = setup
    entries = {(h.UOBJ, h.UNDEF): 7, (h.GOBJ, h.UNDEF): 7, (h.OTHER, h.UNDEF): 0,
               (h.USER, 994): 7, (h.USER, 12345): 7, (h.MASK, h.UNDEF): 0}
    os.setxattr(root, h.DEFAULT, h.encode_acl(entries))
    before_access = os.getxattr(root, h.ACCESS) if h.ACCESS in os.listxattr(root) else None
    _, expected = prepare(setup); apply(setup, expected)
    after = h.decode_acl(read_default(h, root))
    assert after[h.USER, 994] == after[h.USER, 12345] == after[h.GOBJ, h.UNDEF] == 0
    assert after[h.USER, os.getuid()] == after[h.MASK, h.UNDEF] == 7
    assert (os.getxattr(root, h.ACCESS) if h.ACCESS in os.listxattr(root) else None) == before_access


def test_private_cache_symlink_and_files_are_not_modified(setup, tmp_path):
    h, _, _, root, _ = setup
    for name in ('.git', '.aws', '.codex-jax', '.config', '.venv', 'venv', 'node_modules', 'cache'):
        (root / name).mkdir(); (root / name / 'nested').mkdir()
    outside = tmp_path / 'outside'; outside.mkdir()
    (root / 'link').symlink_to(outside, target_is_directory=True)
    file = root / 'handoff.md'; file.write_text('unchanged'); file.chmod(0o600)
    file_before = (file.stat().st_ino, file.stat().st_mode, file.read_bytes(), os.listxattr(file))
    value, expected = prepare(setup); apply(setup, expected)
    assert {row['relative'] for row in value['records']} == {'.', 'docs'}
    assert value['skipped']['private_or_cache'] == 8
    assert value['skipped']['symlink'] == 1
    assert (file.stat().st_ino, file.stat().st_mode, file.read_bytes(), os.listxattr(file)) == file_before
    assert read_default(h, outside) is None
    assert all(read_default(h, root / name) is None for name in ('.git', '.aws', '.venv', 'node_modules'))


@pytest.mark.parametrize('classification', ['foreign_owner', 'read_only', 'mount_boundary'])
def test_owner_readonly_and_mount_boundaries_are_pruned(setup, monkeypatch, classification):
    h, _, _, root, _ = setup
    child = root / 'docs'; child_inode = child.stat().st_ino
    if classification == 'read_only': child.chmod(0o555)
    elif classification == 'foreign_owner':
        original = h.identity
        def identity(fd):
            value = original(fd)
            if value['ino'] == child_inode: value['uid'] = 12345
            return value
        monkeypatch.setattr(h, 'identity', identity)
    else:
        original = h.mount_id
        monkeypatch.setattr(h, 'mount_id', lambda fd: original(fd) + (os.fstat(fd).st_ino == child_inode))
    value, expected = prepare(setup)
    assert value['skipped'][classification] == 1
    assert {row['relative'] for row in value['records']} == {'.'}


def test_plan_hash_mismatch_does_not_create_backup_or_modify_acl(setup):
    h, _, _, root, state = setup
    with pytest.raises(RuntimeError, match='plan changed'):
        apply(setup, '0' * 64)
    assert list(state.iterdir()) == []
    assert read_default(h, root) is None


def test_race_replacement_is_rejected_before_any_mutation_with_backup_retained(setup, monkeypatch, tmp_path):
    h, _, _, root, state = setup
    _, expected = prepare(setup)
    original = h.write_private
    def write(fd, name, document):
        original(fd, name, document)
        if name == 'plan.json':
            (root / 'docs').rename(tmp_path / 'moved')
            (root / 'docs').mkdir()
    monkeypatch.setattr(h, 'write_private', write)
    with pytest.raises(RuntimeError, match='changed'):
        apply(setup, expected)
    assert (state / ('defaults-' + expected) / 'plan.json').exists()
    assert read_default(h, root) is None
    assert read_default(h, root / 'docs') is None
    assert read_default(h, tmp_path / 'moved') is None


def test_partial_apply_is_explicit_and_original_backup_supports_rollback(setup, monkeypatch):
    h, _, _, root, state = setup
    _, expected = prepare(setup)
    original = h.os.setxattr
    calls = 0
    def fail_second(*args, **kwargs):
        nonlocal calls
        calls += 1
        if calls == 2: raise OSError('synthetic xattr failure')
        return original(*args, **kwargs)
    monkeypatch.setattr(h.os, 'setxattr', fail_second)
    with pytest.raises(OSError): apply(setup, expected)
    recovery = state / ('defaults-' + expected)
    backup = (recovery / 'plan.json').read_bytes()
    assert json.loads((recovery / 'journal.json').read_text())['phase'] == 'applying'
    monkeypatch.setattr(h.os, 'setxattr', original)
    rollback(setup, expected)
    assert read_default(h, root) is read_default(h, root / 'docs') is None
    assert (recovery / 'plan.json').read_bytes() == backup


def test_bounded_scan_fails_closed(setup, monkeypatch):
    h, _, _, root, state = setup
    monkeypatch.setattr(h, 'MAX_DIRS', 1)
    with pytest.raises(RuntimeError, match='bounded budget'): prepare(setup)
    assert list(state.iterdir()) == []
    assert read_default(h, root) is None


def test_actual_scope_and_protected_whitelist_are_mandatory(setup):
    h, storage, inputs, root, _ = setup
    selected, excluded = h.choose_all(storage, inputs)
    assert selected == ['agentporter-dev'] and excluded == []
    with pytest.raises(RuntimeError, match='Protected/unknown'): h.authorize(storage, inputs, ['protected'])
    runtime = yaml.safe_load(inputs['runtime']); runtime['allowed_workspace_roots'][0]['writable'] = False
    changed = dict(inputs, runtime=yaml.safe_dump(runtime).encode())
    with pytest.raises(RuntimeError, match='effective writable'): h.plan(storage, changed, ['agentporter-dev'])
    assert h.choose_all(storage, changed) == ([], ['agentporter-dev'])


def test_intervening_default_acl_edit_is_not_overwritten(setup, monkeypatch):
    h, _, _, root, state = setup
    _, expected = prepare(setup)
    original = h.save_journal
    concurrent = h.encode_acl({(h.UOBJ, h.UNDEF): 7, (h.GOBJ, h.UNDEF): 0, (h.OTHER, h.UNDEF): 0})
    def race(fd, document):
        original(fd, document)
        if document['phase'] == 'applying': os.setxattr(root, h.DEFAULT, concurrent)
    monkeypatch.setattr(h, 'save_journal', race)
    with pytest.raises(RuntimeError, match='identity changed|immediately before'): apply(setup, expected)
    assert read_default(h, root) == concurrent
    assert read_default(h, root / 'docs') is None
    assert (state / ('defaults-' + expected) / 'plan.json').exists()


def test_secret_named_directories_are_pruned(setup):
    h, _, _, root, _ = setup
    for name in ('auth.json', 'credentials.json', '.credentials.json', 'id_rsa', 'id_ed25519'):
        (root / name).mkdir()
    value, expected = prepare(setup)
    assert value['skipped']['private_or_cache'] == 5
    apply(setup, expected)
    assert all(read_default(h, root / name) is None for name in
               ('auth.json', 'credentials.json', '.credentials.json', 'id_rsa', 'id_ed25519'))


def test_effective_human_access_honors_named_mask_and_group_membership(setup, monkeypatch):
    h, _, _, root, _ = setup
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
    try:
        real_stat = h.os.fstat
        original_info = real_stat(fd)
        def metadata(descriptor):
            info = real_stat(descriptor)
            if descriptor == fd:
                return SimpleNamespace(st_uid=994, st_gid=12346, st_mode=info.st_mode)
            return info
        monkeypatch.setattr(h.os, 'fstat', metadata)
        denied = {(h.UOBJ, h.UNDEF): 7, (h.GOBJ, h.UNDEF): 7, (h.OTHER, h.UNDEF): 0,
                  (h.USER, os.getuid()): 7, (h.MASK, h.UNDEF): 0}
        real_xattr = h.xattr
        monkeypatch.setattr(h, 'xattr', lambda descriptor, name:
                            h.encode_acl(denied) if descriptor == fd and name == h.ACCESS else real_xattr(descriptor, name))
        assert h.human_access(fd, os.getuid(), {12346}) == 0
        del denied[h.USER, os.getuid()]; denied[h.MASK, h.UNDEF] = 7
        assert h.human_access(fd, os.getuid(), {12346}) == 7
        assert h.human_access(fd, os.getuid(), {12347}) == 0
    finally: os.close(fd)


@pytest.mark.parametrize('active_unit', ['agentporter-dev-autodiscovery.timer', 'agentporter-dev-autodiscovery.service'])
def test_quiet_guard_refuses_active_discovery_without_changing_services(setup, monkeypatch, active_unit):
    h, storage, _, _, _ = setup
    storage.quiet_and_stopped = lambda: None
    calls = []
    def systemctl(argv, **kwargs):
        calls.append(argv)
        return SimpleNamespace(returncode=0 if argv[-1] == active_unit else 3,
                               stdout='active' if argv[-1] == active_unit else 'inactive')
    monkeypatch.setattr(h.subprocess, 'run', systemctl)
    with pytest.raises(RuntimeError, match='Stop discovery'): h.quiet(storage)
    assert all(argv[:2] == ['/usr/bin/systemctl', 'is-active'] for argv in calls)
