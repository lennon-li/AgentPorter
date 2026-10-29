"""BCC discovery uses separate, confined worker settings and scoped project rows."""
import importlib.util
import os
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[2] / 'scripts/autodiscover-bcc.py'
spec = importlib.util.spec_from_file_location('bcc_discovery', SCRIPT)
a = importlib.util.module_from_spec(spec)
spec.loader.exec_module(a)


def test_new_project_gets_bounded_writable_worker_access(tmp_path):
    project = tmp_path / 'new-project'
    project.mkdir()
    fd = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        candidates = a.discover(fd, str(tmp_path), os.getuid())
    finally:
        os.close(fd)
    docs = {
        'workspaces.yaml': {'workspaces': {}},
        'public-client-policy.yaml': {'version': 1, 'workspaces': {}},
        'development-runtime.yaml': {'allowed_workspace_roots': [{'path': '/existing', 'writable': False}]},
    }
    result, _, _ = a.plan(docs, {}, candidates)
    assert result['workspaces.yaml']['workspaces']['new-project']['allow_agent_dispatch']
    assert result['development-runtime.yaml']['allowed_workspace_roots'][-1] == {'path': str(project), 'writable': True}
    ops = result['public-client-policy.yaml']['workspaces']['new-project']['operations']
    assert set(ops) == {'read', 'write', 'git_read', 'exec', 'dispatch', 'dispatch_write'}
    assert not {'https', 'git_write'} & set(ops)


def test_discovery_does_not_follow_aliases_or_include_private_names(tmp_path):
    (tmp_path / 'project').mkdir()
    (tmp_path / '.codex').mkdir()
    (tmp_path / 'alias').symlink_to(tmp_path / 'project', target_is_directory=True)
    fd = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        assert set(a.discover(fd, str(tmp_path), os.getuid())) == {'project'}
    finally:
        os.close(fd)


def test_project_acl_denies_private_content_and_limits_git_metadata(tmp_path):
    import subprocess
    import pwd
    try:
        recipient = pwd.getpwnam('agentporter-bcc-worker').pw_uid
    except KeyError:
        recipient = 12345
    project = tmp_path / 'project'
    project.mkdir()
    (project / 'ordinary.txt').write_text('synthetic')
    (project / '.env').write_text('synthetic private')
    (project / '.git').mkdir()
    (project / '.git/config').write_text('synthetic git')
    with a.directory(project) as fd:
        a.grant_tree(fd, os.getuid(), recipient)
    def acl(path):
        return subprocess.check_output(['/usr/bin/getfacl', '-cpn', str(path)], text=True)
    assert f'user:{recipient}:rw-' in acl(project / 'ordinary.txt')
    assert f'user:{recipient}:---' in acl(project / '.env')
    assert f'user:{recipient}:r--' in acl(project / '.git/config')
