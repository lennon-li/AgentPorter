import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from agentporter import workspace_access as access


def policy(root):
    return SimpleNamespace(workspaces={'project': {'path': str(root)}}, protected_paths=(),
                           capabilities=lambda _: {'writable': True})


def test_acl_plan_apply_rollback_preserves_contents_and_other_effective_rights(tmp_path):
    root = tmp_path / 'source'; root.mkdir(mode=0o700)
    target = root / 'private'; target.write_text('data'); target.chmod(0o600)
    target_uid = 12345
    values = {(access.UOBJ, access.UNDEF): 6, (access.GOBJ, access.UNDEF): 7,
              (access.USER, 12346): 7, (access.MASK, access.UNDEF): 4,
              (access.OTHER, access.UNDEF): 0}
    os.setxattr(target, access.ACCESS, access.encode(values))
    before = os.getxattr(target, access.ACCESS), target.stat().st_mode
    plan = access.plan(policy(root), target_uid, include_ancestors=False)
    access.apply(plan)
    actual = access.decode(os.getxattr(target, access.ACCESS), target.stat().st_mode)
    assert actual[access.USER, target_uid] == 4
    assert actual[access.USER, 12346] & actual[access.MASK, access.UNDEF] == 4
    assert actual[access.GOBJ, access.UNDEF] & actual[access.MASK, access.UNDEF] == 4
    assert target.read_text() == 'data'
    access.apply(plan, rollback=True)
    assert (os.getxattr(target, access.ACCESS), target.stat().st_mode) == before
    assert target.read_text() == 'data'


def test_private_paths_hardlinks_and_symlinks_are_not_granted(tmp_path):
    root = tmp_path / 'source'; root.mkdir()
    (root / '.env').write_text('private')
    (root / '.codex').mkdir(); (root / '.codex/auth.json').write_text('private')
    (root / 'ordinary').write_text('data'); (root / 'ordinary').chmod(0o600)
    os.link(root / 'ordinary', tmp_path / 'external-alias')
    (root / 'link').symlink_to(tmp_path)
    plan = access.plan(policy(root), 12345, include_ancestors=False)
    assert set(plan['records']) == {str(root)}


def test_git_control_tree_receives_no_write_permission(tmp_path):
    root = tmp_path / 'source'; root.mkdir()
    (root / '.git').mkdir(mode=0o700)
    (root / '.git/config').write_text('config'); (root / '.git/config').chmod(0o600)
    plan = access.plan(policy(root), 12345, include_ancestors=False)
    for path, row in plan['records'].items():
        if '.git' in Path(path).parts:
            acl = access.decode(access._unb64(row['after']['access']), 0)
            assert not acl[access.USER, 12345] & 2


def test_changed_acl_is_rejected_before_overwrite(tmp_path):
    root = tmp_path / 'source'; root.mkdir()
    plan = access.plan(policy(root), 12345, include_ancestors=False)
    root.chmod(0o700)
    with pytest.raises(ValueError): access.apply(plan)


def test_existing_service_owned_file_is_not_given_an_equivalent_nonpersistent_acl(tmp_path):
    root = tmp_path / 'source'; root.mkdir()
    file = root / 'private'; file.write_text('data'); file.chmod(0o600)
    plan = access.plan(policy(root), os.getuid(), include_ancestors=False)
    assert str(file) not in plan['records']
    access.apply(plan); access.apply(plan, rollback=True)


def test_explicit_child_deny_cannot_be_bypassed_by_parent_acl_plan(tmp_path):
    root = tmp_path / 'source'; root.mkdir()
    child = root / 'denied'; child.mkdir()
    p = policy(root); p.workspaces['denied'] = {'path': str(child)}
    p.capabilities = lambda name: {'writable': name != 'denied'}
    plan = access.plan(p, 12345, include_ancestors=False)
    row = plan['records'][str(child)]
    assert access.decode(access._unb64(row['after']['access']), 0)[access.USER, 12345] == 5


def test_registry_capabilities_are_compiled_once_for_large_trees(tmp_path):
    root = tmp_path / 'source'; root.mkdir()
    for index in range(100): (root / f'file-{index}').write_text('data')
    p = policy(root); calls = []
    def capabilities(name):
        calls.append(name)
        return {'writable': True}
    p.capabilities = capabilities
    result = access.plan(p, 12345, include_ancestors=False)
    assert result['scanned'] == 101
    assert calls == ['project']


def test_compiled_control_prefixes_preserve_component_boundaries(tmp_path):
    root = tmp_path / 'source'; root.mkdir()
    control = root / 'control'; control.mkdir(); (control / 'child').mkdir()
    ordinary = root / 'control-other'; ordinary.mkdir()
    p = policy(root); p.protected_paths = (control,)
    result = access.plan(p, 12345, include_ancestors=False)
    assert str(control) not in result['records']
    assert str(control / 'child') not in result['records']
    assert str(ordinary) in result['records']


def test_budget_failure_reports_the_limit_and_metadata_counts(tmp_path):
    root = tmp_path / 'source'; root.mkdir(); (root / 'file').write_text('data')
    with pytest.raises(ValueError, match=r'entry budget after 2 entries'):
        access.plan(policy(root), 12345, max_entries=1, include_ancestors=False)


def test_partial_application_rollback_preserves_unapplied_concurrent_acl_change(tmp_path):
    root = tmp_path / 'source'; root.mkdir(mode=0o700)
    for name in ('a', 'b'):
        (root / name).write_text('data'); (root / name).chmod(0o600)
    result = access.plan(policy(root), 12345, include_ancestors=False)
    (root / 'b').chmod(0o640)
    applied = []
    with pytest.raises(ValueError, match='changed after planning'):
        access.apply(result, applied_paths=applied)
    assert applied == [str(root / 'a')]
    access.apply(result, rollback=True, applied_paths=applied)
    assert (root / 'a').stat().st_mode & 0o777 == 0o600
    assert (root / 'b').stat().st_mode & 0o777 == 0o640


def test_failed_default_acl_write_can_restore_partially_changed_directory(tmp_path, monkeypatch):
    root = tmp_path / 'source'; root.mkdir(mode=0o700)
    result = access.plan(policy(root), 12345, include_ancestors=False)
    original = access.os.setxattr
    def fail_default(fd, name, value):
        if name == access.DEFAULT: raise OSError('fixture failure')
        return original(fd, name, value)
    monkeypatch.setattr(access.os, 'setxattr', fail_default)
    applied = []
    with pytest.raises(OSError, match='fixture failure'):
        access.apply(result, applied_paths=applied)
    monkeypatch.setattr(access.os, 'setxattr', original)
    access.apply(result, rollback=True, applied_paths=applied)
    fd = access._open(root, True)
    try: assert access.identity(fd)['access'] is None
    finally: os.close(fd)
    assert root.stat().st_mode & 0o777 == 0o700


def test_metadata_open_rejects_symlink_ancestors_and_parent_components(tmp_path):
    outside = tmp_path / 'outside'; outside.mkdir()
    (outside / 'file').write_text('private')
    link = tmp_path / 'link'; link.symlink_to(outside)
    with pytest.raises(OSError): access._open(link / 'file')
    with pytest.raises(ValueError, match='Noncanonical'):
        access._open(outside / '..' / 'outside' / 'file')
