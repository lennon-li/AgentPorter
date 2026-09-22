"""Named Codex identities for AgentPorter delegation."""

import os
import re
import subprocess

from agentporter.agents.adapters.codex import CodexAdapter
from agentporter.agents.policy import ExecutionPolicy


class NamedCodexAdapter(CodexAdapter):
    """Codex adapter bound to an identity-specific CODEX_HOME."""

    def __init__(
        self,
        *,
        name: str,
        alias: str,
        codex_home: str,
        description: str,
        executable_override=None,
    ):
        super().__init__(executable_override=executable_override)
        self.name = name
        self.alias = alias
        self.codex_home = os.path.expanduser(codex_home)
        self.description = description

    def detect(self) -> dict:
        exe = self.find_executable(["codex", "~/.npm-global/bin/codex", "~/.local/bin/codex"])
        cfg_path = os.path.join(self.codex_home, "config.toml")
        auth_path = os.path.join(self.codex_home, "auth.json")
        identity_ready = os.path.isfile(cfg_path) and os.path.isfile(auth_path)
        is_installed = exe is not None and identity_ready

        cli_version = "unknown"
        if exe is not None:
            try:
                res = subprocess.run([exe, "--version"], capture_output=True, text=True, timeout=5)
                raw = (res.stdout + res.stderr).strip()
                match = re.search(r"(\d+\.\d+\.\d+)", raw)
                cli_version = match.group(1) if match else (raw.splitlines()[0] if raw else "unknown")
            except Exception:
                cli_version = "unknown"

        configured_model = self.default_model
        reasoning_effort = self.reasoning_effort
        if os.path.isfile(cfg_path):
            try:
                with open(cfg_path, "r", encoding="utf-8") as handle:
                    content = handle.read()
                model_match = re.search(r'^\s*model\s*=\s*["\']([^"\']+)["\']', content, re.M)
                if model_match:
                    configured_model = model_match.group(1)
                effort_match = re.search(
                    r'^\s*model_reasoning_effort\s*=\s*["\']([^"\']+)["\']',
                    content,
                    re.M,
                )
                if effort_match:
                    reasoning_effort = effort_match.group(1)
            except Exception:
                pass

        return {
            "executable": exe,
            "is_installed": is_installed,
            "cli_version": cli_version,
            "provider": self.provider,
            "configured_model": configured_model,
            "reasoning_effort": reasoning_effort,
            "codex_home": self.codex_home,
            "identity_ready": identity_ready,
        }

    def build_argv(self, workspace_path: str, packet: str, model: str, reasoning_effort: str, policy=None) -> list[str]:
        exe = self.find_executable(["codex", "~/.npm-global/bin/codex", "~/.local/bin/codex"])
        if not exe:
            raise RuntimeError("Codex CLI executable not found on host")

        policy = policy or ExecutionPolicy()
        sandbox = "workspace-write" if policy.workspace_write else "read-only"
        # The workspace-write sandbox has no network, so a confirmed push needs it enabled.
        network = ["-c", "sandbox_workspace_write.network_access=true"] if policy.git_push else []

        return [
            "env",
            f"CODEX_HOME={self.codex_home}",
            exe,
            "exec",
            "--ephemeral",
            "--sandbox",
            sandbox,
            "--skip-git-repo-check",
            "-c",
            "approval_policy=never",
            *network,
            "-m",
            model,
            "-c",
            f"model_reasoning_effort={reasoning_effort}",
            packet,
        ]


class JaxAdapter(NamedCodexAdapter):
    def __init__(self, executable_override=None):
        super().__init__(
            name="jax",
            alias="Jax",
            codex_home="~/.codex",
            description="Jax: bounded review, debugging, tests, and implementation via Codex CLI",
            executable_override=executable_override,
        )


class LizAdapter(NamedCodexAdapter):
    def __init__(self, executable_override=None):
        super().__init__(
            name="liz",
            alias="Liz",
            codex_home="~/.codex-liz",
            description="Liz: correctness-focused implementation, validation, refactoring, and tests via Codex CLI",
            executable_override=executable_override,
        )
