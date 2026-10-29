"""File publication must not turn a validated edit into a canonical-metadata write."""
import hashlib
import os
from pathlib import Path
import pytest
from agentporter.sandbox import workspace_delta


def publish(root, path, source, expected=None):
    return workspace_delta.publish_workspace_file(root, path, source, expected_sha256=expected)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def fixture_paths(tmp_path):
    root = tmp_path / 'project'
    root.mkdir()
    source = tmp_path / 'quiescent-edit'
    source.write_bytes(b'new content\n')
    return root, source


def test_create_and_replace_preserve_file_mode(tmp_path):
    root, source = fixture_paths(tmp_path)
    publish(root, 'ordinary', source)
    target = root / 'ordinary'
    assert target.read_bytes() == source.read_bytes()
    target.chmod(0o755)
    source.write_bytes(b'updated\n')
    publish(root, 'ordinary', source, digest(b'new content\n'))
    assert target.read_bytes() == b'updated\n'
    assert target.stat().st_mode & 0o7777 == 0o755


@pytest.mark.parametrize('expected', [None, digest(b'stale')])
def test_conflict_keeps_original(tmp_path, expected):
    root, source = fixture_paths(tmp_path)
    (root / 'ordinary').write_bytes(b'owner edit')
    with pytest.raises(PermissionError):
        publish(root, 'ordinary', source, expected)
    assert (root / 'ordinary').read_bytes() == b'owner edit'
    assert sorted(p.name for p in root.iterdir()) == ['ordinary']


def test_destination_hardlink_cannot_change_canonical_git_ref(tmp_path):
    root, source = fixture_paths(tmp_path)
    refs = root / '.git/refs/heads'
    refs.mkdir(parents=True)
    canonical = refs / 'main'
    canonical.write_bytes(b'canonical history')
    os.link(canonical, root / 'alias')
    with pytest.raises(PermissionError):
        publish(root, 'alias', source, digest(b'canonical history'))
    assert canonical.read_bytes() == b'canonical history'


@pytest.mark.parametrize('path', ['.git/HEAD', 'child/.git/config', '../outside', '/absolute', '.env', 'child/credentials.json'])
def test_protected_or_escaping_path_fails_closed(tmp_path, path):
    root, source = fixture_paths(tmp_path)
    with pytest.raises((PermissionError, ValueError)):
        publish(root, path, source)
    assert list(root.iterdir()) == []


def test_symlink_parent_never_writes_outside_workspace(tmp_path):
    root, source = fixture_paths(tmp_path)
    outside = tmp_path / 'outside'
    outside.mkdir()
    (root / 'linked').symlink_to(outside, target_is_directory=True)
    with pytest.raises((PermissionError, OSError)):
        publish(root, 'linked/file', source)
    assert list(outside.iterdir()) == []


def test_symlink_source_is_rejected(tmp_path):
    root, source = fixture_paths(tmp_path)
    link = tmp_path / 'source-alias'
    link.symlink_to(source)
    with pytest.raises((PermissionError, OSError)):
        publish(root, 'ordinary', link)
    assert list(root.iterdir()) == []


@pytest.mark.parametrize('path', ['.envrc', 'deploy.key', 'certificate.pem', '.config/github-copilot/token', '.local/share/opencode/token'])
def test_publication_uses_workspace_secret_policy(tmp_path, path):
    root, source = fixture_paths(tmp_path)
    (root / Path(path).parent).mkdir(parents=True, exist_ok=True)
    with pytest.raises(PermissionError):
        publish(root, path, source)
    assert not (root / path).exists()
