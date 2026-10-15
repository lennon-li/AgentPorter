"""Anthropic Claude Code CLI agent adapter."""

import re
import subprocess
from agentporter.agents.adapters.base import AgentAdapter
from agentporter.agents.policy import ExecutionPolicy


class ClaudeAdapter(AgentAdapter):
    name = "claude"
    alias = "Claude Code"
    provider = "Anthropic"
    description = "Anthropic Claude Code CLI worker"

    # No read-only/model/reasoning controls are claimed until the adapter
    # can enforce them with documented CLI flags.
    supports_read_only = False
    supports_model_override = False
    supports_reasoning_override = False

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
        policy: ExecutionPolicy | None = None,
    ) -> list[str]:
        exe = self.find_executable(["claude", "~/.npm-global/bin/claude", "~/.local/bin/claude"])
        if not exe:
            raise RuntimeError("Claude Code CLI executable not found on host")
        policy = policy or ExecutionPolicy.for_workspace(writable=writable)
        if not policy.workspace_write:
            raise RuntimeError("Claude adapter does not yet enforce read-only execution")
        if model or reasoning_effort:
            raise RuntimeError("Claude adapter does not yet enforce model/reasoning overrides")
        # Per-invocation permissions only; never enable bypassPermissions.
        # Exclude project permission overrides; managed organization policy wins.
        denied = [f"Bash({command}*)" for command in policy.denied_commands()]
        return [
            exe, "--setting-sources", "user",
            "--settings", '{"permissions":{"ask":[]}}',
            "--permission-mode", "dontAsk",
            "--allowedTools", "Read", "Grep", "Glob", "Edit", "Write",
            "NotebookEdit", "Bash", "--disallowedTools", *denied,
            "-p", packet,
        ]
