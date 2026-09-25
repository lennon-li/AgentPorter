"""OpenAI Codex CLI agent adapter."""

import os
import re
import subprocess
from agentporter.agents.adapters.base import AgentAdapter
from agentporter.agents.policy import ExecutionPolicy


class CodexAdapter(AgentAdapter):
    name = "codex"
    alias = "Codex"
    provider = "OpenAI"
    description = "OpenAI Codex CLI worker"

    supports_read_only = True
    supports_model_override = True
    supports_reasoning_override = True

    def capabilities(self) -> list[str]:
        return ["code_generation", "code_review", "refactoring", "debugging", "verification"]

    def detect(self) -> dict:
        exe = self.find_executable(["codex", "~/.npm-global/bin/codex", "~/.local/bin/codex"])
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

        configured_model = "unknown"
        reasoning_effort = "unknown"
        cfg_path = os.path.expanduser("~/.codex/config.toml")
        if os.path.exists(cfg_path):
            try:
                with open(cfg_path, "r", encoding="utf-8") as f:
                    cfg = f.read()
                m = re.search(r'^\s*model\s*=\s*["\']([^"\']+)["\']', cfg, re.M)
                if m:
                    configured_model = m.group(1)
                eff = re.search(
                    r'^\s*model_reasoning_effort\s*=\s*["\']([^"\']+)["\']',
                    cfg,
                    re.M,
                )
                if eff:
                    reasoning_effort = eff.group(1)
            except Exception:
                pass

        return {
            "executable": exe,
            "is_installed": is_installed,
            "cli_version": cli_version,
            "provider": self.provider,
            "configured_model": configured_model,
            "reasoning_effort": reasoning_effort,
        }

    def build_argv(
        self,
        workspace_path: str,
        packet: str,
        model: str = "",
        reasoning_effort: str = "",
        writable: bool = True,
    ) -> list[str]:
        exe = self.find_executable(["codex", "~/.npm-global/bin/codex", "~/.local/bin/codex"])
        if not exe:
            raise RuntimeError("Codex CLI executable not found on host")

        if isinstance(writable, ExecutionPolicy):
            policy = writable
        else:
            policy = ExecutionPolicy.for_workspace(writable=bool(writable))
        sandbox = "workspace-write" if policy.workspace_write else "read-only"
        network = (
            ["-c", "sandbox_workspace_write.network_access=true"]
            if policy.workspace_write and policy.git_push
            else []
        )
        cmd = [
            exe,
            "exec",
            "--sandbox",
            sandbox,
            "-c",
            "approval_policy=never",
            *network,
        ]
        if model:
            cmd.extend(["-m", model])
        if reasoning_effort:
            cmd.extend(["-c", f"model_reasoning_effort={reasoning_effort}"])
        cmd.append(packet)
        return cmd
