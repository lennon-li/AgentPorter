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
    assert "--untracked-files=all" in calls[0]["argv"]
    assert all(c["network_access"] is False for c in calls)
    # Executable repository hooks must be neutralized even when .git is writable.
    for call in calls:
        assert call["argv"][call["argv"].index("core.hooksPath=/dev/null") - 1] == "-c"


@pytest.mark.skipif(not BWRAP_USABLE, reason="Kernel Bubblewrap namespace unavailable")
def test_git_status_forces_untracked_files_despite_repository_config(tmp_path):
    root = tmp_path / "repo"
    root.mkdir()
    subprocess.run(["git", "init", "-q", "-b", "main", str(root)], check=True)
    subprocess.run(["git", "-C", str(root), "config", "status.showUntrackedFiles", "no"], check=True)
    (root / "hidden-by-config.txt").write_text("untracked\n")
    sandbox = BubblewrapSandbox(tmp_path / "state")
    registry = WorkspaceRegistry({"repo": {"path": str(root), "writable": True}})
    result = create_git_tools(registry, sandbox).git_status("repo")
    assert "hidden-by-config.txt" in result


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
