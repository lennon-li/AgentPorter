"""OpenCode CLI agent adapter."""

import os
import re
import json
import subprocess
from agentporter.agents.adapters.base import AgentAdapter
from agentporter.agents.policy import ExecutionPolicy


class OpenCodeAdapter(AgentAdapter):
    name = "opencode"
    alias = "OpenCode"
    provider = "OpenCode"
    description = "OpenCode CLI worker; provider/model depend on local OpenCode configuration"

    supports_read_only = False
    supports_model_override = True
    supports_reasoning_override = False

    def capabilities(self) -> list[str]:
        return ["code_generation", "code_search", "testing", "code_review"]

    def detect(self) -> dict:
        exe = self.find_executable(["opencode", "~/.npm-global/bin/opencode", "~/.local/bin/opencode"])
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
        provider = self.provider
        cfg_path = os.path.expanduser("~/.config/opencode/opencode.json")
        if os.path.exists(cfg_path):
            try:
                with open(cfg_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                if isinstance(data.get("model"), str) and data["model"]:
                    configured_model = data["model"]
                    prefix = configured_model.split("/", 1)[0]
                    provider = prefix or self.provider
            except Exception:
                pass

        return {
            "executable": exe,
            "is_installed": is_installed,
            "cli_version": cli_version,
            "provider": provider,
            "configured_model": configured_model,
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
        exe = self.find_executable(["opencode", "~/.npm-global/bin/opencode", "~/.local/bin/opencode"])
        if not exe:
            raise RuntimeError("OpenCode CLI executable not found on host")
        policy = policy or ExecutionPolicy.for_workspace(writable=writable)
        if not policy.workspace_write:
            raise RuntimeError("OpenCode adapter does not yet enforce read-only execution")
        if reasoning_effort:
            raise RuntimeError("OpenCode adapter does not yet enforce reasoning overrides")
        # OpenCode changed its permission schema in v2. Never silently launch
        # without the per-run profile on an unknown/undetectable version.
        try:
            version = subprocess.run(
                [exe, "--version"], capture_output=True, text=True, timeout=5,
                check=True,
            ).stdout.strip()
        except (OSError, subprocess.SubprocessError) as exc:
            raise RuntimeError("Cannot verify OpenCode permission schema") from exc
        match = re.fullmatch(r"(?:opencode\s+)?v?([12])\.\d+\.\d+(?:[-+][\w.-]+)?", version)
        if not match:
            raise RuntimeError("Unsupported OpenCode permission schema version")
        major = int(match.group(1))
        if major == 1:
            permissions = {
                "edit": "allow", "external_directory": "deny",
                "bash": {"*": "allow", **{
                    f"{command}*": "deny" for command in policy.denied_commands()
                }},
            }
            profile = {"agent": {"dispatch": {
                "description": "Bounded workspace worker", "mode": "primary",
                "permission": permissions,
            }}}
        else:
            permissions = [
                {"action": "edit", "resource": "*", "effect": "allow"},
                {"action": "external_directory", "resource": "*", "effect": "deny"},
                {"action": "shell", "resource": "*", "effect": "allow"},
                *({"action": "shell", "resource": f"{command}*", "effect": "deny"}
                  for command in policy.denied_commands()),
            ]
            profile = {"agents": {"dispatch": {
                "mode": "primary", "permissions": permissions,
            }}}
        cmd = ["/usr/bin/env", "OPENCODE_CONFIG_CONTENT=" + json.dumps(profile),
               exe, "run", "--agent", "dispatch"]
        if major == 2:
            cmd.append("--standalone")
        if model:
            cmd.extend(["-m", model])
        cmd.append(packet)
        return cmd
