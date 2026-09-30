"""Unit tests for the execution policy and adapter argv translation."""

import json
from pathlib import Path

import pytest

from agentporter.agents.adapters.claude import ClaudeAdapter
from agentporter.agents.adapters.codex import CodexAdapter
from agentporter.agents.adapters.codex_identity import JaxAdapter, LizAdapter
from agentporter.agents.adapters.copilot import CopilotAdapter
from agentporter.agents.adapters.opencode import OpenCodeAdapter
from agentporter.agents.command_guard import find_denied
from agentporter.agents.policy import ExecutionPolicy

WS = "/work/space"
READ_ONLY = ExecutionPolicy.for_workspace(writable=False)


@pytest.fixture
def fake_exe(tmp_path: Path) -> str:
    exe = tmp_path / "fake-cli"
    exe.write_text("#!/bin/sh\n")
    exe.chmod(0o755)
    return str(exe)


def test_default_policy_constrains_sensitive_actions():
    policy = ExecutionPolicy()
    assert policy.workspace_write and policy.shell and policy.git_read
    assert not (policy.git_commit or policy.git_push or policy.destructive)
    denied = policy.denied_commands()
    assert "git push" in denied
    assert "git commit" in denied
    assert "git commit" not in ExecutionPolicy(git_commit=True).denied_commands()
    assert not READ_ONLY.workspace_write


def test_claude_model_override_and_non_interactive(fake_exe):
    adapter = ClaudeAdapter(executable_override=fake_exe)
    assert adapter.build_argv(WS, "PACKET") == [fake_exe, "-p", "PACKET"]
    if adapter.supports_model_override:
        assert adapter.build_argv(WS, "PACKET", "sonnet") == [fake_exe, "--model", "sonnet", "-p", "PACKET"]
    else:
        with pytest.raises(RuntimeError, match="model"):
            adapter.build_argv(WS, "PACKET", "sonnet")
    assert not adapter.supports_read_only
    assert not adapter.supports_reasoning_override
    with pytest.raises(RuntimeError, match="read-only"):
        adapter.build_argv(WS, "P", writable=False)
    with pytest.raises(RuntimeError, match="reasoning"):
        adapter.build_argv(WS, "P", reasoning_effort="high")


@pytest.mark.parametrize("adapter_cls", [CodexAdapter, JaxAdapter, LizAdapter])
def test_codex_family_keeps_workspace_write_and_never_approval(adapter_cls, fake_exe):
    argv = adapter_cls(executable_override=fake_exe).build_argv(WS, "P", "gpt-x", "xhigh")
    assert argv[argv.index("--sandbox") + 1] == "workspace-write"
    assert "approval_policy=never" in argv
    assert argv[argv.index("-m") + 1] == "gpt-x"
    assert "model_reasoning_effort=xhigh" in argv

    read_only = adapter_cls(executable_override=fake_exe).build_argv(WS, "P", "gpt-x", "xhigh", READ_ONLY)
    assert read_only[read_only.index("--sandbox") + 1] == "read-only"


def test_jax_and_liz_identity_homes_stay_separate(fake_exe):
    jax = JaxAdapter(executable_override=fake_exe).build_argv(WS, "P", "m", "high")
    liz = LizAdapter(executable_override=fake_exe).build_argv(WS, "P", "m", "high")
    assert jax[:2] == ["env", f"CODEX_HOME={Path('~/.codex').expanduser()}"]
    assert liz[:2] == ["env", f"CODEX_HOME={Path('~/.codex-liz').expanduser()}"]


def test_copilot_argv_scoped_with_deny_rules(fake_exe):
    argv = CopilotAdapter(executable_override=fake_exe).build_argv(WS, "PACKET", "gpt-x", "high")
    assert argv[argv.index("-C") + 1] == WS
    assert argv[argv.index("--prompt") + 1] == "PACKET"
    assert "--silent" in argv
    assert "--allow-all-tools" in argv
    assert "--allow-all-paths" not in argv and "--yolo" not in argv and "--allow-all" not in argv
    assert "--deny-tool=shell(git push)" in argv
    assert argv[argv.index("--reasoning-effort") + 1] == "high"
    assert "--deny-tool=write" in CopilotAdapter(executable_override=fake_exe).build_argv(
        WS, "P", "gpt-x", "high", READ_ONLY
    )


def test_copilot_auto_model_omits_reasoning_effort(fake_exe):
    argv = CopilotAdapter(executable_override=fake_exe).build_argv(WS, "P", "auto", "high")
    assert "--reasoning-effort" not in argv


def test_opencode_supported_controls_fail_closed(fake_exe):
    adapter = OpenCodeAdapter(executable_override=fake_exe)
    argv = adapter.build_argv(WS, "PACKET", "vertex/x")
    assert argv == [fake_exe, "run", "-m", "vertex/x", "PACKET"]
    assert not adapter.supports_read_only
    assert not adapter.supports_reasoning_override
    with pytest.raises(RuntimeError, match="read-only"):
        adapter.build_argv(WS, "P", writable=False)
    with pytest.raises(RuntimeError, match="reasoning"):
        adapter.build_argv(WS, "P", reasoning_effort="medium")


@pytest.mark.parametrize("command", [
    "git push --dry-run",
    "cd sub && git push origin main",
    "git -C /repo push",
    'bash -c "git commit -m x"',
    "git commit -m x",
    "rm -rf build",
    "sudo apt install foo",
])
def test_command_guard_blocks_sensitive_commands(command):
    assert find_denied(command, ExecutionPolicy().denied_commands())


@pytest.mark.parametrize("command", [
    "git status --short",
    "git log --oneline",
    "python3 -m pytest -q",
    "rm -f .agentporter-permission-smoke",
    "echo sudo",
    "sum file",
])
def test_command_guard_allows_routine_commands(command):
    assert find_denied(command, ExecutionPolicy().denied_commands()) is None


def test_command_guard_hook_exit_codes():
    import subprocess
    import sys
    from agentporter.agents import command_guard

    denied = json.dumps(ExecutionPolicy().denied_commands())
    def run(cmd):
        event = json.dumps({"tool_name": "Bash", "tool_input": {"command": cmd}})
        return subprocess.run(
            [sys.executable, command_guard.__file__, denied], input=event, capture_output=True, text=True
        ).returncode
    assert run("git push") == 2
    assert run("git status") == 0


def test_commit_and_push_require_explicit_confirmation():
    default = ExecutionPolicy.for_workspace(writable=True)
    assert {"git commit", "git push"} <= set(default.denied_commands())

    confirmed = ExecutionPolicy.for_workspace(writable=True, allow_commit=True, allow_push=True)
    denied = confirmed.denied_commands()
    assert "git commit" not in denied and "git push" not in denied
    assert find_denied("git push origin main", denied) is None
    assert find_denied("git push --force origin main", denied) == "git push --force"
    assert find_denied("git remote add x url", denied) == "git remote"

    read_only = ExecutionPolicy.for_workspace(writable=False, allow_commit=True, allow_push=True)
    assert not read_only.git_commit and not read_only.git_push


def test_codex_network_enabled_only_for_confirmed_push(fake_exe):
    push = ExecutionPolicy.for_workspace(writable=True, allow_push=True)
    for adapter_cls in (CodexAdapter, JaxAdapter, LizAdapter):
        default_argv = adapter_cls(executable_override=fake_exe).build_argv(WS, "P", "m", "high")
        push_argv = adapter_cls(executable_override=fake_exe).build_argv(WS, "P", "m", "high", push)
        assert "sandbox_workspace_write.network_access=true" not in default_argv
        assert "sandbox_workspace_write.network_access=true" in push_argv
