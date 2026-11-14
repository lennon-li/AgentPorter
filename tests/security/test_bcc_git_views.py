"""Real disposable Git views: readable history, separate inodes, no owner control files."""
import hashlib
import json
from pathlib import Path
import subprocess
import pytest
from tests.security.test_approved_git_commit import backend
from tests.security.test_git_approval_state import git


def metadata(root):
    return {str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in (root/'.git').rglob('*') if p.is_file()}


@pytest.mark.parametrize('writable', [False, True])
def test_private_history_has_real_objects_refs_and_stash_but_no_host_hooks_or_worktrees(tmp_path, writable):
    root, _, sandbox, _ = backend(tmp_path)
    (root/'ordinary').write_text('owner stash fixture')
    git(root, 'stash', 'push', '-qm', 'owner fixture')
    (root/'.git/hooks/owner-hook').write_text('PRIVATE OWNER HOOK')
    host_worktree = tmp_path/'host-linked-worktree'
    git(root, 'worktree', 'add', '--detach', str(host_worktree), 'HEAD')
    before = metadata(root)
    head = git(root, 'rev-parse', 'HEAD')
    stash = git(root, 'rev-parse', 'refs/stash')
    canonical_inode = (root/'.git/HEAD').stat().st_ino
    code = '''import json,os,subprocess
from pathlib import Path
def git(*args):return subprocess.check_output(['git',*args],stderr=subprocess.DEVNULL).decode().strip()
p=Path('/workspace/.git')
print(json.dumps({'head':git('rev-parse','HEAD'),'head_inode':(p/'HEAD').stat().st_ino,
 'direct_object':git('cat-file','-t',HEAD),'stash':git('rev-parse','refs/stash'),
 'hooks_absent':not (p/'hooks').exists(),'worktrees_absent':not (p/'worktrees').exists(),
 'alternates_absent':not (p/'objects/info/alternates').exists(),
 'host_home_absent':not Path('/home/yeli').exists(),
 'hooks_disabled':git('config','core.hooksPath')=='/dev/null'}))
'''.replace('HEAD)', repr(head)+')')
    result = sandbox.run(str(root), ['/usr/bin/python3', '-c', code], writable=writable, timeout_seconds=40)
    assert result['exit_code'] == 0, result
    value = json.loads(result['stdout'])
    assert value.pop('head') == head and value.pop('stash') == stash
    assert value.pop('head_inode') != canonical_inode
    assert value.pop('direct_object') == 'commit'
    assert all(value.values()), value
    assert metadata(root) == before


@pytest.mark.parametrize('layout', ['alternates', 'linked_worktree'])
@pytest.mark.parametrize('writable', [False, True])
def test_external_git_administration_fails_closed(tmp_path, layout, writable):
    root, _, sandbox, _ = backend(tmp_path)
    if layout == 'alternates':
        (root/'.git/objects/info/alternates').write_text('/outside/objects\n')
    else:
        import shutil
        shutil.rmtree(root/'.git')
        (root/'.git').write_text('gitdir: /outside/metadata\n')
    before = {str(p.relative_to(root)): p.read_bytes() for p in root.rglob('*') if p.is_file()}
    with pytest.raises(PermissionError):
        sandbox.run(str(root), ['/usr/bin/true'], writable=writable)
    assert before == {str(p.relative_to(root)): p.read_bytes() for p in root.rglob('*') if p.is_file()}


@pytest.mark.parametrize('mutation', ['ref', 'stash'])
def test_raw_history_mutation_cannot_publish_any_canonical_metadata(tmp_path, mutation):
    root,_,sandbox,_=backend(tmp_path)
    before=metadata(root);ordinary=(root/'ordinary').read_bytes()
    if mutation=='ref':
        code="from pathlib import Path; Path('/workspace/.git/HEAD').write_text('ref: refs/heads/unapproved\\n'); print('PRIVATE_MUTATION_EXECUTED')"
    else:
        code="from pathlib import Path; import subprocess; Path('/workspace/ordinary').write_text('private stash'); subprocess.run(['git','stash','push','-qm','private stash'],check=True); print('PRIVATE_MUTATION_EXECUTED')"
    result=sandbox.run(str(root),['/usr/bin/python3','-c',code],writable=True)
    assert 'PRIVATE_MUTATION_EXECUTED' in result['stdout'],result
    assert result['exit_code']!=0,result
    assert metadata(root)==before
    assert (root/'ordinary').read_bytes()==ordinary
