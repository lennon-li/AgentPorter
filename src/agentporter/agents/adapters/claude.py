"""Anthropic Claude Code CLI agent adapter."""

import re
import subprocess
from agentporter.agents.adapters.base import AgentAdapter


class ClaudeAdapter(AgentAdapter):
    name = "claude"
    alias = "Claude"
    provider = "Anthropic"
    default_model = "claude-3-7-sonnet"
    reasoning_effort = "high"
    description = "Anthropic Claude Code CLI for high-consequence reasoning and review"

    def capabilities(self) -> list[str]:
        return ["deep_reasoning", "architecture", "senior_code_review"]

    def detect(self) -> dict:
        exe = self.find_executable(["claude", "~/.npm-global/bin/claude", "~/.local/bin/claude"])
        is_installed = exe is not None

        cli_version = "unknown"
        if is_installed:
            try:
                res = subprocess.run([exe, "--version"], capture_output=True, text=True, timeout=5)
                raw = (res.stdout + res.stderr).strip()
                m = re.search(r'(\d+\.\d+\.\d+)', raw)
                cli_version = m.group(1) if m else (raw.splitlines()[0] if raw else "unknown")
            except Exception:
                cli_version = "unknown"

        return {
            "executable": exe,
            "is_installed": is_installed,
            "cli_version": cli_version,
            "provider": self.provider,
            "configured_model": self.default_model,
            "reasoning_effort": self.reasoning_effort,
        }

    def build_argv(self, workspace_path: str, packet: str, model: str, reasoning_effort: str) -> list[str]:
        exe = self.find_executable(["claude", "~/.npm-global/bin/claude", "~/.local/bin/claude"])
        if not exe:
            raise RuntimeError("Claude Code CLI executable not found on host")

        return [exe, "-p", packet]
