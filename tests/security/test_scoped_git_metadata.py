"""Trusted Git commands may mutate repository control files; generic shell may not."""

import shutil
import subprocess

import pytest

from agentporter.sandbox.bubblewrap import BubblewrapSandbox
from agentporter.tools.git import create_git_tools
from agentporter.workspaces.registry import WorkspaceRegistry
from tests._support import BWRAP_USABLE


def _git_overlay(args):
    return any(
        args[i:i + 3] == ["--ro-bind", "/tmp/placeholder/.git", "/workspace/.git"]
        for i in range(len(args) - 2)
    )


def test_generic_sandbox_keeps_git_metadata_readonly(tmp_path):
    root = tmp_path / "repo"
    (root / ".git").mkdir(parents=True)
    sandbox = BubblewrapSandbox(tmp_path / "state")
    generic = sandbox.build_bwrap_args(str(root))
    assert ["--ro-bind", str(root / ".git"), "/workspace/.git"] == generic[
        generic.index(str(root / ".git")) - 1:generic.index(str(root / ".git")) + 2
    ]
    scoped = sandbox.build_bwrap_args(
        str(root), writable=True, git_metadata_writable=True
    )
    assert not any(
        scoped[i:i + 3] == ["--ro-bind", str(root / ".git"), "/workspace/.git"]
        for i in range(len(scoped) - 2)
    )
    assert "--unshare-net" in scoped
    assert "--clearenv" in scoped


def test_git_mutations_select_trusted_metadata_mode(tmp_path, monkeypatch):
    ws = tmp_path / "repo"
    ws.mkdir()
    sandbox = BubblewrapSandbox(tmp_path / "state")
    calls = []

    def fake_run(**kwargs):
        calls.append(kwargs)
        return {"exit_code": 0, "stdout": "", "stderr": ""}

    monkeypatch.setattr(sandbox, "run", fake_run)
    registry = WorkspaceRegistry({"repo": {"path": str(ws), "writable": True}})
    git = create_git_tools(registry, sandbox)
    git.git_status("repo")
    git.git_add("repo", ["file.txt"])
    git.git_checkout("repo", "review", create=True)
    assert [c["git_metadata_writable"] for c in calls] == [False, True, True]
    assert all(c["network_access"] is False for c in calls)
    # Executable repository hooks must be neutralized even when .git is writable.
    for call in calls:
        assert call["argv"][call["argv"].index("core.hooksPath=/dev/null") - 1] == "-c"


@pytest.mark.skipif(not BWRAP_USABLE, reason="Kernel Bubblewrap namespace unavailable")
def test_scoped_git_add_and_checkout_work_without_opening_generic_shell(tmp_path):
    root = tmp_path / "repo"
    root.mkdir()
    subprocess.run(["git", "init", "-q", "-b", "main"], cwd=root, check=True)
    subprocess.run(["git", "config", "user.name", "Fixture"], cwd=root, check=True)
    subprocess.run(["git", "config", "user.email", "fixture@example.invalid"], cwd=root, check=True)
    (root / "tracked.txt").write_text("initial\n")
    subprocess.run(["git", "add", "tracked.txt"], cwd=root, check=True)
    subprocess.run(["git", "commit", "-qm", "fixture"], cwd=root, check=True)
    (root / "pending.txt").write_text("pending\n")

    sandbox = BubblewrapSandbox(tmp_path / "state")
    registry = WorkspaceRegistry({"repo": {"path": str(root), "writable": True}})
    tools = create_git_tools(registry, sandbox)
    assert "Git error" not in tools.git_add("repo", ["pending.txt"])
    staged = subprocess.check_output(["git", "diff", "--cached", "--name-only"], cwd=root, text=True)
    assert "pending.txt" in staged
    assert "Git error" not in tools.git_checkout("repo", "review", create=True)
    current = subprocess.check_output(["git", "branch", "--show-current"], cwd=root, text=True).strip()
    assert current == "review"

    # The same workspace remains non-publication capable via generic execution.
    probe = sandbox.run(
        str(root),
        ["python3", "-c", "from pathlib import Path; Path('/workspace/.git/HEAD').write_text('wrong')"],
        writable=True,
    )
    assert probe["exit_code"] != 0
    assert subprocess.check_output(["git", "branch", "--show-current"], cwd=root, text=True).strip() == "review"


@pytest.mark.parametrize("custom_hooks_path", [False, True])
@pytest.mark.skipif(not BWRAP_USABLE, reason="Kernel Bubblewrap namespace unavailable")
def test_git_checkout_does_not_run_repo_post_checkout_hook(tmp_path, custom_hooks_path):
    """A malicious repo must not bypass locked commit through post-checkout."""
    root = tmp_path / "repo"
    root.mkdir()
    subprocess.run(["git", "init", "-q", "-b", "main"], cwd=root, check=True)
    subprocess.run(["git", "config", "user.name", "Fixture"], cwd=root, check=True)
    subprocess.run(["git", "config", "user.email", "fixture@example.invalid"], cwd=root, check=True)
    (root / "safe.txt").write_text("safe\n")
    subprocess.run(["git", "add", "--", "safe.txt"], cwd=root, check=True)
    subprocess.run(["git", "commit", "-qm", "initial"], cwd=root, check=True)

    hooks = root / ".git/hooks" if not custom_hooks_path else root / ".evil-hooks"
    hooks.mkdir(exist_ok=True)
    hook = hooks / "post-checkout"
    hook.write_text("#!/bin/sh\ngit commit --allow-empty -qm HOOK_ESCAPE\n")
    hook.chmod(0o755)
    if custom_hooks_path:
        subprocess.run(["git", "config", "core.hooksPath", str(hooks)], cwd=root, check=True)

    initial = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip()
    sandbox = BubblewrapSandbox(tmp_path / "state")
    registry = WorkspaceRegistry({"repo": {"path": str(root), "writable": True}})
    tools = create_git_tools(registry, sandbox)
    result = tools.git_checkout("repo", "reviewed", create=True)
    assert "Git error" not in result
    assert subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip() == initial
    assert subprocess.check_output(["git", "branch", "--show-current"], cwd=root, text=True).strip() == "reviewed"
    assert "HOOK_ESCAPE" not in subprocess.check_output(["git", "log", "-1", "--format=%s"], cwd=root, text=True)


@pytest.mark.skipif(not BWRAP_USABLE, reason="Kernel Bubblewrap namespace unavailable")
def test_generic_shell_can_create_private_disposable_repository(tmp_path):
    root = tmp_path / 'workspace'
    root.mkdir()
    sandbox = BubblewrapSandbox(tmp_path / 'sandbox-state')
    script = ('set -eu; mkdir /tmp/nested; cd /tmp/nested; '
              'git init -q; printf synthetic > file.txt; git add file.txt; '
              'git -c user.name=synthetic -c user.email=synthetic@example.invalid '
              'commit -qm fixture')
    result = subprocess.run(sandbox.build_bwrap_args(str(root), writable=True) +
                            ['--', '/bin/sh', '-c', script], capture_output=True, timeout=20)
    assert result.returncode == 0, result.stderr
    assert list(root.iterdir()) == []


@pytest.mark.skipif(not BWRAP_USABLE, reason='Kernel Bubblewrap namespace unavailable')
def test_legacy_generic_execution_cannot_write_canonical_workspace(tmp_path):
    root = tmp_path / 'workspace'
    root.mkdir()
    (root / 'ordinary').write_text('owner original')
    sandbox = BubblewrapSandbox(tmp_path / 'state')
    result = sandbox.run(str(root), ['/bin/sh', '-c', 'printf unsafe > /workspace/ordinary'], writable=True)
    assert result['exit_code'] != 0
    assert (root / 'ordinary').read_text() == 'owner original'


@pytest.mark.parametrize('nested', [False, True])
@pytest.mark.skipif(not BWRAP_USABLE, reason='Kernel Bubblewrap namespace unavailable')
def test_generic_task_cannot_remount_workspace_writable(tmp_path, nested):
    root = tmp_path / 'workspace'
    root.mkdir()
    (root / 'ordinary').write_text('owner original')
    code = """import ctypes,pathlib
library = ctypes.CDLL(None, use_errno=True)
library.mount(None, b'/workspace', None, 4096 | 32, None)
pathlib.Path('/workspace/ordinary').write_text('bypass')
"""
    arguments = ['/usr/bin/python3', '-I', '-S', '-c', code]
    if nested:
        arguments = ['/usr/bin/unshare', '--user', '--map-root-user', '--mount', '--', *arguments]
    result = BubblewrapSandbox(tmp_path / 'state').run(str(root), arguments, writable=True)
    assert result['exit_code'] != 0
    assert (root / 'ordinary').read_text() == 'owner original'

@pytest.mark.skipif(not BWRAP_USABLE, reason="Kernel Bubblewrap namespace unavailable")
def test_generic_shell_cannot_change_existing_nested_repository_history(tmp_path):
    root = tmp_path / 'workspace'
    nested = root / 'project'
    nested.mkdir(parents=True)
    subprocess.run(['git', 'init', '-q', str(nested)], check=True)
    git = ['git', '-c', 'user.name=synthetic', '-c', 'user.email=synthetic@example.invalid']
    subprocess.run(git + ['commit', '--allow-empty', '-qm', 'initial'], cwd=nested, check=True)
    before = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=nested)
    sandbox = BubblewrapSandbox(tmp_path / 'sandbox-state')
    result = subprocess.run(
        sandbox.build_bwrap_args(str(root), writable=True)
        + ['--', '/bin/sh', '-c', 'cd /workspace/project && git -c user.name=synthetic -c user.email=synthetic@example.invalid commit --allow-empty -qm unauthorized'],
        capture_output=True, timeout=20,
    )
    after = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=nested)
    assert after == before, 'generic command changed existing nested repository history'
    assert result.returncode != 0

@pytest.mark.skipif(not BWRAP_USABLE, reason="Kernel Bubblewrap namespace unavailable")
def test_generic_shell_cannot_change_canonical_ref_through_hardlink(tmp_path):
    root = tmp_path / 'workspace'
    root.mkdir()
    subprocess.run(['git', 'init', '-q', '-b', 'main', str(root)], check=True)
    git = ['git', '-c', 'user.name=synthetic', '-c', 'user.email=synthetic@example.invalid']
    subprocess.run(git + ['commit', '--allow-empty', '-qm', 'initial'], cwd=root, check=True)
    before = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=root)
    subprocess.run(git + ['commit', '--allow-empty', '-qm', 'second'], cwd=root, check=True)
    after = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=root)
    import os
    os.link(root / '.git/refs/heads/main', root / 'ordinary-looking-file')
    sandbox = BubblewrapSandbox(tmp_path / 'sandbox-state')
    result = subprocess.run(
        sandbox.build_bwrap_args(str(root), writable=True)
        + ['--', '/bin/sh', '-c', 'printf "%s\\n" "$1" > /workspace/ordinary-looking-file', 'sh', before.decode().strip()],
        capture_output=True, timeout=20,
    )
    assert subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=root) == after, 'read-only Git mount bypassed through writable inode alias'
    assert result.returncode != 0

@pytest.mark.skipif(not BWRAP_USABLE, reason='Kernel Bubblewrap namespace unavailable')
def test_trusted_checkout_cannot_execute_filter_with_git_write_rights(tmp_path):
    root = tmp_path / 'repo'
    root.mkdir()
    git = ['git', '-c', 'user.name=synthetic', '-c', 'user.email=synthetic@example.invalid']
    subprocess.run(git + ['init', '-q', '-b', 'main'], cwd=root, check=True)
    (root / '.gitattributes').write_text('safe.txt filter=synthetic\n')
    (root / 'safe.txt').write_text('base')
    subprocess.run(git + ['add', '.'], cwd=root, check=True)
    subprocess.run(git + ['commit', '-qm', 'base'], cwd=root, check=True)
    subprocess.run(git + ['checkout', '-qb', 'target'], cwd=root, check=True)
    (root / 'safe.txt').write_text('target')
    subprocess.run(git + ['commit', '-qam', 'target'], cwd=root, check=True)
    subprocess.run(git + ['checkout', '-q', 'main'], cwd=root, check=True)
    malicious = ('git -c user.name=synthetic -c user.email=synthetic@example.invalid '
                 'commit-tree HEAD^{tree} -p HEAD -m UNAPPROVED_FILTER | '
                 'xargs git update-ref refs/heads/unauthorized; cat')
    subprocess.run(git + ['config', 'filter.synthetic.smudge', malicious], cwd=root, check=True)
    sandbox = BubblewrapSandbox(tmp_path / 'state')
    tools = create_git_tools(WorkspaceRegistry({'repo': {'path': str(root), 'writable': True}}), sandbox)
    tools.git_checkout('repo', 'target')
    assert not (root / '.git/refs/heads/unauthorized').exists(), 'repository filter created unauthorized canonical commit/ref'

@pytest.mark.parametrize('filter_key', ['clean', 'smudge', 'process'])
@pytest.mark.skipif(not BWRAP_USABLE, reason='Kernel Bubblewrap namespace unavailable')
def test_trusted_git_rejects_executable_filters_from_included_config(tmp_path, filter_key):
    root = tmp_path / 'repo'
    root.mkdir()
    subprocess.run(['git', 'init', '-q', str(root)], check=True)
    (root / 'ordinary').write_text('safe')
    included = root / '.git/included-config'
    included.write_text('[filter "synthetic"]\n\t' + filter_key + ' = touch /workspace/.git/UNAPPROVED_FILTER\n')
    subprocess.run(['git', 'config', 'include.path', str(included)], cwd=root, check=True)
    # Absolute host paths are deliberately unavailable inside the sandbox;
    # use the equivalent repo-relative include the worker can actually read.
    subprocess.run(['git', 'config', 'include.path', 'included-config'], cwd=root, check=True)
    sandbox = BubblewrapSandbox(tmp_path / 'state')
    tools = create_git_tools(WorkspaceRegistry({'repo': {'path': str(root), 'writable': True}}), sandbox)
    result = tools.git_add('repo', ['ordinary'])
    assert result.startswith('Git error'), result
    assert 'executable filters' in result
    assert not (root / '.git/UNAPPROVED_FILTER').exists()
    assert not (root / '.git/index').exists()


@pytest.mark.skipif(not BWRAP_USABLE, reason='Kernel Bubblewrap namespace unavailable')
def test_trusted_checkout_cannot_write_other_history_through_reflog_alias(tmp_path):
    import os
    root = tmp_path / 'repo'
    other = tmp_path / 'outside'
    command = ['git', '-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid']
    for directory in (root, other):
        subprocess.run(command + ['init', '-q', '-b', 'main', str(directory)], check=True)
        subprocess.run(command + ['commit', '--allow-empty', '-qm', 'initial'], cwd=directory, check=True)
    target = other / '.git/refs/heads/main'
    before = target.read_bytes()
    (root / '.git/logs/HEAD').unlink()
    os.link(target, root / '.git/logs/HEAD')
    tools = create_git_tools(WorkspaceRegistry({'repo': {'path': str(root), 'writable': True}}),
                             BubblewrapSandbox(tmp_path / 'state'))
    try:
        tools.git_checkout('repo', 'reviewed', create=True)
    except PermissionError:
        pass
    assert target.read_bytes() == before, 'trusted checkout changed unrelated history through a reflog inode alias'


@pytest.mark.skipif(not BWRAP_USABLE, reason='Kernel Bubblewrap namespace unavailable')
def test_trusted_staging_cannot_redirect_worktree_into_git_metadata(tmp_path):
    root = tmp_path / 'repo'
    root.mkdir()
    subprocess.run(['git', 'init', '-q', str(root)], check=True)
    (root / 'config').write_text('reviewed ordinary file')
    subprocess.run(['git', 'config', 'core.worktree', '/workspace/.git'], cwd=root, check=True)
    sandbox = BubblewrapSandbox(tmp_path / 'state')
    tools = create_git_tools(WorkspaceRegistry({'repo': {'path': str(root), 'writable': True}}), sandbox)
    result = tools.git_add('repo', ['config'])
    assert not result.startswith('Git error'), result
    staged = subprocess.check_output(['git', '--git-dir=' + str(root / '.git'),
                                     '--work-tree=' + str(root), 'show', ':config'], cwd=root)
    assert staged == b'reviewed ordinary file', 'repository config redirected an ordinary staged path into protected Git config'
