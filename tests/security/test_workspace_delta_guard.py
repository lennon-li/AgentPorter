"""Staged workspace writes must not publish unapproved Git metadata."""
import os
import pytest
from agentporter.sandbox.workspace_delta import validate_workspace_delta


def test_ordinary_project_changes_are_eligible(tmp_path):
    (tmp_path / 'src').mkdir()
    (tmp_path / 'src' / 'main.py').write_text('print(1)')
    validate_workspace_delta(tmp_path)


@pytest.mark.parametrize('name', ['.git', '.GiT', '.env', 'credentials.json'])
def test_private_and_git_metadata_changes_are_rejected(tmp_path, name):
    nested = tmp_path / 'new-project'
    nested.mkdir()
    (nested / name).write_text('synthetic')
    with pytest.raises(PermissionError):
        validate_workspace_delta(tmp_path)


def test_symlink_and_hardlink_changes_fail_closed(tmp_path):
    target = tmp_path / 'target'
    target.write_text('synthetic')
    (tmp_path / 'link').symlink_to(target)
    with pytest.raises(PermissionError):
        validate_workspace_delta(tmp_path)
    (tmp_path / 'link').unlink()
    os.link(target, tmp_path / 'hardlink')
    with pytest.raises(PermissionError):
        validate_workspace_delta(tmp_path)


def test_real_overlay_rejects_nested_commit_without_touching_original(tmp_path):
    import subprocess
    from tests._support import BWRAP_USABLE
    if not BWRAP_USABLE or not os.path.exists('/opt/agentporter-bcc/bin/bwrap'):
        pytest.skip('BCC overlay sandbox unavailable')
    lower, upper, work = (tmp_path / name for name in ('lower', 'upper', 'work'))
    for path in (lower, upper, work):
        path.mkdir()
    command = ['/opt/agentporter-bcc/bin/bwrap', '--unshare-user', '--unshare-pid', '--unshare-net']
    for path in ('/usr', '/bin', '/lib', '/lib64'):
        command += ['--ro-bind', path, path]
    command += ['--dev', '/dev', '--overlay-src', str(lower), '--overlay', str(upper), str(work), '/workspace',
                '--', '/bin/sh', '-c',
                'set -eu; mkdir /workspace/project; cd /workspace/project; git init -q; '
                'printf synthetic > file; git add file; '
                'git -c user.name=test -c user.email=test@example.invalid commit -qm test']
    try:
        result = subprocess.run(command, capture_output=True, timeout=20)
        assert result.returncode == 0, result.stderr
        with pytest.raises(PermissionError):
            validate_workspace_delta(upper)
        assert not (lower / 'project').exists()
    finally:
        # Overlayfs creates an inaccessible work/work directory; pytest owns
        # this synthetic directory and must restore access for cleanup.
        internal_work = work / 'work'
        if internal_work.exists():
            internal_work.chmod(0o700)


def test_overlay_opaque_directory_fails_closed(tmp_path):
    changed = tmp_path / 'subdir'
    changed.mkdir()
    try:
        os.setxattr(changed, 'user.overlay.opaque', b'y')
    except OSError:
        pytest.skip('filesystem does not support user xattrs')
    with pytest.raises(PermissionError):
        validate_workspace_delta(tmp_path)


def test_overlay_whiteout_file_fails_closed(tmp_path):
    changed = tmp_path / 'ordinary'
    changed.touch()
    try:
        os.setxattr(changed, 'user.overlay.whiteout', b'y')
    except OSError:
        pytest.skip('filesystem does not support user xattrs')
    with pytest.raises(PermissionError):
        validate_workspace_delta(tmp_path)


def test_ordinary_copy_up_origin_metadata_is_allowed(tmp_path):
    changed = tmp_path / 'ordinary'
    changed.write_text('edited')
    try:
        os.setxattr(changed, 'user.overlay.origin', b'synthetic')
    except OSError:
        pytest.skip('filesystem does not support user xattrs')
    validate_workspace_delta(tmp_path)


def test_real_overlay_keeps_canonical_ref_unchanged_through_alias(tmp_path):
    import subprocess
    bwrap = '/opt/agentporter-bcc/bin/bwrap'
    if not os.path.isfile(bwrap):
        pytest.skip('BCC overlay sandbox unavailable')
    lower, upper, work = (tmp_path / name for name in ('lower', 'upper', 'work'))
    for directory in (lower, upper, work):
        directory.mkdir()
    refs = lower / '.git/refs/heads'
    refs.mkdir(parents=True)
    ref = refs / 'main'
    ref.write_text('canonical-before\n')
    os.link(ref, lower / 'alias')
    command = [bwrap, '--unshare-all', '--unshare-net', '--die-with-parent']
    for directory in ('/usr', '/bin', '/lib', '/lib64'):
        if os.path.exists(directory):
            command += ['--ro-bind', directory, directory]
    command += ['--dev', '/dev', '--overlay-src', str(lower), '--overlay', str(upper), str(work), '/workspace',
                '--', '/bin/sh', '-c', 'printf changed > /workspace/alias']
    try:
        result = subprocess.run(command, capture_output=True, timeout=20)
        assert result.returncode == 0, result.stderr
        assert ref.read_text() == 'canonical-before\n'
        assert (lower / 'alias').read_text() == 'canonical-before\n'
        assert (upper / 'alias').read_text() == 'changed'
    finally:
        internal_work = work / 'work'
        if internal_work.exists():
            internal_work.chmod(0o700)


@pytest.mark.parametrize('path', ['.envrc', 'deploy.key', 'certificate.pem', '.config/github-copilot/token', '.local/share/opencode/token'])
def test_delta_uses_workspace_secret_policy(tmp_path, path):
    from pathlib import Path
    target = tmp_path / Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text('synthetic credential')
    with pytest.raises(PermissionError):
        validate_workspace_delta(tmp_path)


def test_privileged_file_mode_is_rejected_before_publication(tmp_path):
    target = tmp_path / 'ordinary'
    target.write_text('synthetic')
    target.chmod(0o4755)
    with pytest.raises(PermissionError):
        validate_workspace_delta(tmp_path)


def test_oversized_changed_file_is_rejected_before_publication(tmp_path):
    with (tmp_path / 'ordinary').open('wb') as stream:
        stream.truncate(64 * 1024 * 1024 + 1)
    with pytest.raises(PermissionError):
        validate_workspace_delta(tmp_path)
