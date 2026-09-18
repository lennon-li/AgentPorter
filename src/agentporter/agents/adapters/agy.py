"""Antigravity (agy) CLI agent adapter."""

import re
import subprocess
from agentporter.agents.adapters.base import AgentAdapter


class AgyAdapter(AgentAdapter):
    name = "agy"
    alias = "Antigravity"
    provider = "Antigravity"
    description = "Antigravity CLI worker; upstream provider/model depend on local configuration"

    supports_read_only = False
    supports_model_override = False
    supports_reasoning_override = False

    def capabilities(self) -> list[str]:
        return ["survey", "synthesis", "audit", "exploration"]

    def detect(self) -> dict:
        exe = self.find_executable(["agy", "~/.local/bin/agy", "/usr/local/bin/agy"])
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
        exe = self.find_executable(["agy", "~/.local/bin/agy", "/usr/local/bin/agy"])
        if not exe:
            raise RuntimeError("Agy CLI executable not found on host")
        if not writable:
            raise RuntimeError("Agy adapter does not yet enforce read-only execution")
        if model or reasoning_effort:
            raise RuntimeError("Agy adapter does not yet enforce model/reasoning overrides")
        return [exe, "-p", packet]
