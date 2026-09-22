"""OpenCode CLI agent adapter."""

import os
import re
import json
import subprocess
from agentporter.agents.adapters.base import AgentAdapter
from agentporter.agents.policy import ExecutionPolicy


class OpenCodeAdapter(AgentAdapter):
    name = "opencode"
    alias = "Wei / Wong"
    provider = "Google Vertex AI"
    default_model = "vertex/gemini-3.7-flash"
    reasoning_effort = "medium"
    description = "OpenCode CLI routed via Google Vertex AI / Go for high-volume implementation"

    def capabilities(self) -> list[str]:
        return ["fast_implementation", "code_search", "testing"]

    def detect(self) -> dict:
        exe = self.find_executable(["opencode", "~/.npm-global/bin/opencode", "~/.local/bin/opencode"])
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
        provider = self.provider

        # Check active ~/.config/opencode/opencode.json
        cfg_path = os.path.expanduser("~/.config/opencode/opencode.json")
        if os.path.exists(cfg_path):
            try:
                with open(cfg_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                if "model" in data and isinstance(data["model"], str) and data["model"]:
                    configured_model = data["model"]
                    if "vertex" in configured_model.lower():
                        provider = "Google Vertex AI"
            except Exception:
                pass

        return {
            "executable": exe,
            "is_installed": is_installed,
            "cli_version": cli_version,
            "provider": provider,
            "configured_model": configured_model,
            "reasoning_effort": self.reasoning_effort,
        }

    def build_argv(self, workspace_path: str, packet: str, model: str, reasoning_effort: str, policy=None) -> list[str]:
        exe = self.find_executable(["opencode", "~/.npm-global/bin/opencode", "~/.local/bin/opencode"])
        if not exe:
            raise RuntimeError("OpenCode CLI executable not found on host")

        policy = policy or ExecutionPolicy()
        # Inline config is deep-merged over the user's opencode.json. `opencode
        # run` rejects "ask" rules, so routine actions must be explicit allows.
        bash = {"*": "allow", "rm *": "allow"} if policy.shell else {"*": "deny"}
        for prefix in policy.denied_commands():
            bash.update({prefix: "deny", f"{prefix} *": "deny"})
        config = {
            "permission": {
                "edit": "allow" if policy.workspace_write else "deny",
                "bash": bash,
            }
        }
        return [
            "env",
            f"OPENCODE_CONFIG_CONTENT={json.dumps(config)}",
            exe,
            "run",
            "--dir",
            workspace_path,
            "-m",
            model,
            packet,
        ]
