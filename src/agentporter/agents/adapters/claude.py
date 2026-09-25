"""Anthropic Claude Code CLI agent adapter."""

import json
import re
import shlex
import subprocess
import sys
from pathlib import Path

from agentporter.agents import command_guard
from agentporter.agents.adapters.base import AgentAdapter
from agentporter.agents.policy import ExecutionPolicy


class ClaudeAdapter(AgentAdapter):
    name = "claude"
    alias = "Claude Code"
    provider = "Anthropic"
<<<<<<< HEAD
    description = "Anthropic Claude Code CLI worker"

    # No read-only/model/reasoning controls are claimed until the adapter
    # can enforce them with documented CLI flags.
    supports_read_only = False
    supports_model_override = False
    supports_reasoning_override = False
=======
    default_model = "sonnet"
    reasoning_effort = "high"
    description = "Anthropic Claude Code CLI for high-consequence reasoning and review"
    EFFORT_LEVELS = ("low", "medium", "high", "xhigh", "max")
>>>>>>> origin/main

    def capabilities(self) -> list[str]:
        return ["code_generation", "code_review", "architecture", "debugging"]

    def detect(self) -> dict:
        exe = self.find_executable(["claude", "~/.npm-global/bin/claude", "~/.local/bin/claude"])
        is_installed = exe is not None
        cli_version = "unknown"
        if is_installed:
            try:
                res = subprocess.run([exe, "--version"], capture_output=True, text=True, timeout=5)
                raw = (res.stdout + res.stderr).strip()
                m = re.search(r"(\d+\.\d+\.\d+)", raw)
                cli_version = m.group(1) if m else (raw.splitlines()[0] if raw else "unknown")
            except Exception:
                pass
        return {
            "executable": exe,
            "is_installed": is_installed,
            "cli_version": cli_version,
            "provider": self.provider,
            "configured_model": "unknown",
            "reasoning_effort": "unknown",
        }

<<<<<<< HEAD
    def build_argv(
        self,
        workspace_path: str,
        packet: str,
        model: str = "",
        reasoning_effort: str = "",
        writable: bool = True,
    ) -> list[str]:
        exe = self.find_executable(["claude", "~/.npm-global/bin/claude", "~/.local/bin/claude"])
        if not exe:
            raise RuntimeError("Claude Code CLI executable not found on host")
        if not writable:
            raise RuntimeError("Claude adapter does not yet enforce read-only execution")
        if model or reasoning_effort:
            raise RuntimeError("Claude adapter does not yet enforce model/reasoning overrides")
        return [exe, "-p", packet]
=======
    def build_argv(self, workspace_path: str, packet: str, model: str, reasoning_effort: str, policy=None) -> list[str]:
        exe = self.find_executable(["claude", "~/.npm-global/bin/claude", "~/.local/bin/claude"])
        if not exe:
            raise RuntimeError("Claude Code CLI executable not found on host")

        policy = policy or ExecutionPolicy()
        # acceptEdits auto-approves file edits only inside the working
        # directory and Bash is pre-allowed. A pre-allowed Bash outranks
        # --disallowedTools/ask rules in this CLI, so sensitive prefixes are
        # enforced by a PreToolUse hook. Anything that would prompt is denied.
        denied = policy.denied_commands()
        cmd = [
            exe,
            "--permission-mode",
            "acceptEdits" if policy.workspace_write else "plan",
            "--permission-prompts",
            "none",
        ]
        if policy.shell:
            cmd.extend(["--allowedTools", "Bash"])
        cmd.extend(["--settings", self._guard_settings(denied)])
        cmd.append("--disallowedTools")
        cmd.extend(f"Bash({prefix} *)" for prefix in denied)
        if model:
            cmd.extend(["--model", model])
        if reasoning_effort in self.EFFORT_LEVELS:
            cmd.extend(["--effort", reasoning_effort])
        cmd.extend(["-p", packet])
        return cmd

    @staticmethod
    def _guard_settings(denied: list[str]) -> str:
        # Run the guard by path so the hook does not import the agentporter package.
        hook = " ".join(
            shlex.quote(part)
            for part in (sys.executable, str(Path(command_guard.__file__)), json.dumps(denied))
        )
        return json.dumps({
            "hooks": {
                "PreToolUse": [
                    {"matcher": "Bash", "hooks": [{"type": "command", "command": hook}]}
                ]
            }
        })
>>>>>>> origin/main
