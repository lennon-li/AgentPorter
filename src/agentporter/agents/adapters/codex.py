"""OpenAI Codex CLI agent adapter."""

import os
import re
import subprocess
from agentporter.agents.adapters.base import AgentAdapter


class CodexAdapter(AgentAdapter):
    name = "codex"
    alias = "Jax / Vision"
    provider = "OpenAI"
    default_model = "gpt-5.6-luna"
    reasoning_effort = "high"
    description = "OpenAI Codex CLI agent for bounded implementation and review"

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
                m = re.search(r'(\d+\.\d+\.\d+)', raw)
                cli_version = m.group(1) if m else (raw.splitlines()[0] if raw else "unknown")
            except Exception:
                cli_version = "unknown"

        configured_model = self.default_model
        reasoning_effort = self.reasoning_effort

        # Inspect local ~/.codex/config.toml
        cfg_path = os.path.expanduser("~/.codex/config.toml")
        if os.path.exists(cfg_path):
            try:
                with open(cfg_path, "r", encoding="utf-8") as f:
                    content = f.read()
                m = re.search(r'^\s*model\s*=\s*[\"\']([^\"\']+)[\"\']', content, re.M)
                if m:
                    configured_model = m.group(1)
                eff = re.search(r'^\s*model_reasoning_effort\s*=\s*[\"\']([^\"\']+)[\"\']', content, re.M)
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

    def build_argv(self, workspace_path: str, packet: str, model: str, reasoning_effort: str) -> list[str]:
        exe = self.find_executable(["codex", "~/.npm-global/bin/codex", "~/.local/bin/codex"])
        if not exe:
            raise RuntimeError("Codex CLI executable not found on host")

        return [
            exe, "exec",
            "--sandbox", "workspace-write",
            "--skip-git-repo-check",
            "-c", "approval_policy=never",
            "-m", model,
            "-c", f"model_reasoning_effort={reasoning_effort}",
            packet
        ]
