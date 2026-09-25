"""Anthropic Claude Code CLI agent adapter."""

import re
import json
import shlex
import subprocess
from pathlib import Path
from agentporter.agents.adapters.base import AgentAdapter
from agentporter.agents.policy import ExecutionPolicy


class ClaudeAdapter(AgentAdapter):
    name = "claude"
    alias = "Claude Code"
    provider = "Anthropic"
    description = "Anthropic Claude Code CLI worker"

    supports_read_only = True
    supports_model_override = True
    supports_reasoning_override = True

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

        if isinstance(writable, ExecutionPolicy):
            policy = writable
        else:
            policy = ExecutionPolicy.for_workspace(writable=bool(writable))
        permission_mode = "acceptEdits" if policy.workspace_write else "plan"

        denied = json.dumps(policy.denied_commands())
        guard = Path(__file__).resolve().parents[1] / "command_guard.py"
        settings = {
            "hooks": {
                "PreToolUse": [{
                    "matcher": "Bash",
                    "hooks": [{
                        "type": "command",
                        "command": f"python3 {shlex.quote(str(guard))} {shlex.quote(denied)}",
                    }],
                }]
            }
        }

        allowed_tools = ["Bash"]
        if not policy.git_push:
            allowed_tools.append("Bash(git push *)")
        if not policy.git_commit:
            allowed_tools.append("Bash(git commit *)")

        args = [
            exe,
            "--permission-mode",
            permission_mode,
            "--permission-prompts",
            "none",
            "--allowedTools",
            *allowed_tools,
            "--settings",
            json.dumps(settings),
        ]
        if model:
            args.extend(["--model", model])
        if reasoning_effort in {"low", "medium", "high", "xhigh", "max"}:
            args.extend(["--effort", reasoning_effort])
        args.extend(["-p", packet])
        return args
