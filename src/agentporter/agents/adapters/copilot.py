"""GitHub Copilot CLI agent adapter."""

import os
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

    def build_argv(
        self,
        workspace_path: str,
        packet: str,
        model: str = "",
        reasoning_effort: str = "",
        policy=None,
        *,
        writable: bool = True,
    ) -> list[str]:
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
        ]
        # An empty model keeps the profile's configured default.
        if model and model != "auto":
            args.extend(["--model", model])
            if reasoning_effort:
                args.extend(["--reasoning-effort", reasoning_effort])
        # Deny rules take precedence over --allow-all-tools. File tools stay
        # confined to -C because --allow-all-paths is never passed.
        policy = policy or ExecutionPolicy.for_workspace(writable=writable)
        args.extend(f"--deny-tool=shell({prefix})" for prefix in policy.denied_commands())
        if not policy.workspace_write:
            args.append("--deny-tool=write")
        return args


class PhilAdapter(CopilotAdapter):
    """Copilot CLI bound to Phil's own authenticated COPILOT_HOME profile."""

    name = "phil"
    alias = "Phil"
    description = "Phil: implementation, code review, and GitHub-native work via GitHub Copilot CLI"

    def __init__(self, executable_override=None, copilot_home: str = "~/.copilot-phil"):
        super().__init__(executable_override=executable_override)
        self.copilot_home = os.path.expanduser(copilot_home)

    def capabilities(self) -> list[str]:
        return ["implementation", "code_review", "github_workflows"]

    def detect(self) -> dict:
        detection = super().detect()
        profile_ready = os.path.isdir(self.copilot_home)
        detection["is_installed"] = bool(detection["is_installed"] and profile_ready)
        detection["copilot_home"] = self.copilot_home
        detection["profile_ready"] = profile_ready
        return detection

    def build_argv(self, *args, **kwargs) -> list[str]:
        return [
            "env",
            f"COPILOT_HOME={self.copilot_home}",
            f"PHIL_COPILOT_HOME={self.copilot_home}",
            *super().build_argv(*args, **kwargs),
        ]
