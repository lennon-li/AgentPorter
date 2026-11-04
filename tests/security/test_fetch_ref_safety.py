"""Exercise the actual offline fetch programs with real Git, without networking."""
import json
import subprocess
import sys

import pytest

from agentporter.git_fetches import _TRACK, _UPDATE


@pytest.mark.parametrize('algorithm', ['sha1', 'sha256'])
@pytest.mark.parametrize('kind', ['direct', 'symbolic', 'late_symbolic', 'changed', 'absent'])
def test_tracking_update_never_redirects_into_owner_branch(tmp_path, algorithm, kind):
    def git(*args):
        result = subprocess.run(['/usr/bin/git', '-C', str(tmp_path), *args],
                                text=True, capture_output=True, check=True)
        return result.stdout.strip()
    git('init', '-q', '--object-format=' + algorithm)
    git('config', 'user.name', 'Fixture')
    git('config', 'user.email', 'fixture@example.invalid')
    (tmp_path / 'file').write_text('one')
    git('add', 'file'); git('commit', '-qm', 'one')
    old = git('rev-parse', 'HEAD')
    (tmp_path / 'file').write_text('two')
    git('commit', '-qam', 'two')
    new = git('rev-parse', 'HEAD')
    git('update-ref', 'refs/heads/owner', old)
    ref = 'refs/remotes/origin/main'
    if kind == 'symbolic':
        git('symbolic-ref', ref, 'refs/heads/owner')
    elif kind != 'absent':
        git('update-ref', ref, new if kind == 'changed' else old)
    tracking = subprocess.run([sys.executable, '-I', '-S', '-c',
        _TRACK.replace('/workspace', str(tmp_path)), ref, str(len(old))],
        capture_output=True, text=True, timeout=10)
    assert (tracking.returncode != 0) == (kind == 'symbolic')
    if kind == 'late_symbolic':
        git('symbolic-ref', ref, 'refs/heads/owner')
    payload = {'expected_head': new, 'expected_tree': 'fixture', 'branch': 'fixture',
               'parameters': {'tracking_ref': ref, 'remote_oid': new,
                              'old_oid': '0' * len(old) if kind == 'absent' else old}}
    inspector = "head=" + repr(new) + ";tree='fixture';branch='fixture';environment=" + repr({
        'PATH': '/usr/bin:/bin', 'HOME': '/nonexistent', 'GIT_CONFIG_NOSYSTEM': '1',
        'GIT_CONFIG_GLOBAL': '/dev/null', 'GIT_NO_REPLACE_OBJECTS': '1',
        'GIT_NO_LAZY_FETCH': '1', 'GIT_TERMINAL_PROMPT': '0'})
    result = subprocess.run([sys.executable, '-I', '-S', '-c',
        _UPDATE.replace('/workspace', str(tmp_path)), json.dumps(payload), inspector],
        capture_output=True, text=True, timeout=15)
    assert git('rev-parse', 'refs/heads/owner') == old
    if kind in {'symbolic', 'late_symbolic'}:
        assert result.returncode != 0
        assert git('symbolic-ref', ref) == 'refs/heads/owner'
    elif kind == 'changed':
        assert result.returncode != 0
        assert git('rev-parse', ref) == new
    else:
        assert result.returncode == 0, result.stderr
        assert git('rev-parse', ref) == new
