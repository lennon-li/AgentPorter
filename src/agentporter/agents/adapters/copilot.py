"""GitHub Copilot CLI agent adapter."""

import re
import subprocess

from agentporter.agents.adapters.base import AgentAdapter
from agentporter.agents.policy import ExecutionPolicy


class CopilotAdapter(AgentAdapter):
    name = "copilot"
    alias = "GitHub Copilot"
    provider = "GitHub Copilot"
    default_model = "auto"
    reasoning_effort = "medium"
    description = "GitHub Copilot CLI agent for non-interactive coding, review, and repository tasks"

    def capabilities(self) -> list[str]:
        return ["implementation", "code_review", "code_search", "testing"]

    def detect(self) -> dict:
        exe = self.find_executable(["copilot", "~/.local/bin/copilot", "~/.npm-global/bin/copilot"])
        is_installed = exe is not None

        cli_version = "unknown"
        if is_installed:
            try:
                res = subprocess.run([exe, "--version"], capture_output=True, text=True, timeout=5)
                raw = (res.stdout + res.stderr).strip()
                match = re.search(r"(\d+\.\d+\.\d+)", raw)
                cli_version = match.group(1) if match else (raw.splitlines()[0] if raw else "unknown")
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

    def build_argv(self, workspace_path: str, packet: str, model: str, reasoning_effort: str, policy=None) -> list[str]:
        exe = self.find_executable(["copilot", "~/.local/bin/copilot", "~/.npm-global/bin/copilot"])
        if not exe:
            raise RuntimeError("GitHub Copilot CLI executable not found on host")

        args = [
            exe,
            "-C",
            workspace_path,
            "--prompt",
            packet,
            "--silent",
            "--allow-all-tools",
            "--model",
            model,
        ]
        # Deny rules take precedence over --allow-all-tools. File tools stay
        # confined to -C because --allow-all-paths is never passed.
        policy = policy or ExecutionPolicy()
        args.extend(f"--deny-tool=shell({prefix})" for prefix in policy.denied_commands())
        if not policy.workspace_write:
            args.append("--deny-tool=write")
        if model != "auto":
            args.extend(["--reasoning-effort", reasoning_effort])
        return args
