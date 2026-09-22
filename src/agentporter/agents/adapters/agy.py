"""Antigravity (agy) CLI agent adapter."""

import os
import json
import re
import subprocess
from agentporter.agents.adapters.base import AgentAdapter


class AgyAdapter(AgentAdapter):
    name = "agy"
    alias = "Argie"
    provider = "Google AI Pro"
    default_model = "Gemini 3.8 Flash (Medium)"
    reasoning_effort = "medium"
    description = "Antigravity CLI for research, synthesis, and audit consulting"

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
                m = re.search(r'(\d+\.\d+\.\d+)', raw)
                cli_version = m.group(1) if m else (raw.splitlines()[0] if raw else "unknown")
            except Exception:
                cli_version = "unknown"

        configured_model = self.default_model
        cfg_path = os.path.expanduser("~/.gemini/antigravity-cli/settings.json")
        if os.path.exists(cfg_path):
            try:
                with open(cfg_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                if "model" in data and data["model"]:
                    configured_model = data["model"]
            except Exception:
                pass

        return {
            "executable": exe,
            "is_installed": is_installed,
            "cli_version": cli_version,
            "provider": self.provider,
            "configured_model": configured_model,
            "reasoning_effort": self.reasoning_effort,
        }

    def build_argv(self, workspace_path: str, packet: str, model: str, reasoning_effort: str) -> list[str]:
        exe = self.find_executable(["agy", "~/.local/bin/agy", "/usr/local/bin/agy"])
        if not exe:
            raise RuntimeError("Agy CLI executable not found on host")

        cmd = [exe, "--mode", "plan", "--sandbox"]
        if model:
            cmd.extend(["--model", model])
        if reasoning_effort and not any(f"({lvl})" in (model or "") for lvl in ["Low", "Medium", "High"]):
            cmd.extend(["--effort", reasoning_effort.lower()])
        cmd.extend(["-p", packet])
        return cmd

