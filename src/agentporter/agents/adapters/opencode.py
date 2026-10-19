"""OpenCode CLI agent adapter."""

import os
import re
import json
import stat
import subprocess
from agentporter.agents.adapters.base import AgentAdapter
from agentporter.agents.policy import ExecutionPolicy
from agentporter.agents.parallel_search import opencode_mcp_config


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

    def _launch_profile(
        self,
        workspace_path: str,
        writable: bool = True,
        policy: ExecutionPolicy | None = None,
    ) -> tuple[str, int, dict]:
        exe = self.find_executable(["opencode", "~/.npm-global/bin/opencode", "~/.local/bin/opencode"])
        if not exe:
            raise RuntimeError("OpenCode CLI executable not found on host")
        policy = policy or ExecutionPolicy.for_workspace(writable=writable)
        if not policy.workspace_write:
            raise RuntimeError("OpenCode adapter does not yet enforce read-only execution")
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
        return exe, major, profile

    def runtime_env(
        self,
        workspace_path: str,
        writable: bool = True,
        policy: ExecutionPolicy | None = None,
        *, parallel_search_enabled: bool = False,
    ) -> dict[str, str]:
        """Return the per-launch permissions profile outside the process argv."""
        _, _, profile = self._launch_profile(workspace_path, writable=writable, policy=policy)
        if parallel_search_enabled:
            profile.update(opencode_mcp_config())
        env = os.environ.copy()
        env["OPENCODE_CONFIG_CONTENT"] = json.dumps(profile, separators=(",", ":"))
        return env

    def build_argv(
        self,
        workspace_path: str,
        packet: str,
        model: str = "",
        reasoning_effort: str = "",
        writable: bool = True,
        policy: ExecutionPolicy | None = None,
    ) -> list[str]:
        exe, major, _ = self._launch_profile(workspace_path, writable=writable, policy=policy)
        if reasoning_effort:
            raise RuntimeError("OpenCode adapter does not yet enforce reasoning overrides")
        cmd = [exe, "run", "--agent", "dispatch"]
        if major == 2:
            cmd.append("--standalone")
        if model:
            cmd.extend(["-m", model])
        cmd.append(packet)
        return cmd


class WeiAdapter(OpenCodeAdapter):
    """Wei uses an isolated OpenCode credential and verified free models."""

    name = "wei"
    alias = "Wei"
    provider = "opencode"
    description = "Wei: coding, review, and tests via the local OpenCode CLI"
    default_model = "opencode/glm-5.3-flash-free"
    free_models = frozenset({
        "opencode/beam-free",
        "opencode/deepseek-v4.1-flash-free",
        "opencode/glm-5.3-flash-free",
        "opencode/longcat-2.5-preview-free",
        "opencode/mimo-v2.6-flash-free",
        "opencode/nemotron-3-ultra-free",
        "opencode/nemotron-3.5-lightning-free",
        "opencode/nemotron-3.5-super-vl-free",
        "opencode/space-bunny-free",
    })

    @staticmethod
    def _key_path() -> str:
        return os.path.expanduser("~/.config/opencode/wei-key")

    def _read_key(self) -> str:
        path = self._key_path()
        try:
            metadata = os.stat(path)
        except OSError as exc:
            raise RuntimeError("Wei credential file is unavailable") from exc
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_mode & 0o077:
            raise RuntimeError("Wei credential file must be a private regular file")
        with open(path, "r", encoding="utf-8") as handle:
            key = handle.read().strip()
        if not key:
            raise RuntimeError("Wei credential file is empty")
        return key

    def detect(self) -> dict:
        result = super().detect()
        try:
            self._read_key()
            credential_ready = True
        except RuntimeError:
            credential_ready = False
        result.update({
            "is_installed": bool(result["is_installed"] and credential_ready),
            "provider": self.provider,
            "configured_model": self.default_model,
            "credential_ready": credential_ready,
        })
        return result

    def runtime_env(self, workspace_path: str, writable: bool = True,
                    policy: ExecutionPolicy | None = None,
                    *, parallel_search_enabled: bool = False) -> dict[str, str]:
        env = super().runtime_env(
            workspace_path, writable=writable, policy=policy,
            parallel_search_enabled=parallel_search_enabled,
        )
        profile = json.loads(env["OPENCODE_CONFIG_CONTENT"])
        profile.setdefault("provider", {}).setdefault("opencode", {}).setdefault(
            "options", {}
        )["apiKey"] = self._read_key()
        env["OPENCODE_CONFIG_CONTENT"] = json.dumps(profile, separators=(",", ":"))
        return env

    def build_argv(
        self,
        workspace_path: str,
        packet: str,
        model: str = "",
        reasoning_effort: str = "",
        writable: bool = True,
        policy: ExecutionPolicy | None = None,
    ) -> list[str]:
        selected = model or self.default_model
        if selected not in self.free_models:
            raise ValueError("Wei accepts only the configured free OpenCode models")
        self._read_key()
        return super().build_argv(
            workspace_path, packet, model=selected,
            reasoning_effort=reasoning_effort, writable=writable, policy=policy,
        )
