"""Fail-closed, short-lived Codex CLI launch profile for delegated workers.

This removes per-user MCP tools/plugins/hooks from the CLI configuration. It does
not make the worker process a host-level security sandbox.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
import tomllib

_ROOT_KEYS = (
    "model", "model_provider", "model_reasoning_effort", "openai_base_url",
    "chatgpt_base_url", "model_context_window", "model_max_output_tokens",
    "model_auto_compact_token_limit", "disable_response_storage",
    "forced_login_method", "forced_chatgpt_workspace_id",
)
_PROVIDER_KEYS = (
    "name", "base_url", "env_key", "wire_api", "http_headers",
    "env_http_headers", "query_params", "request_max_retries",
    "stream_max_retries", "stream_idle_timeout_ms",
    "requires_openai_auth",
)
_ALLOWED_ENV = (
    "PATH", "HOME", "USER", "LOGNAME", "LANG", "LC_ALL", "LC_CTYPE",
    "TERM", "SSL_CERT_FILE", "SSL_CERT_DIR", "OPENAI_API_KEY",
    "OPENAI_ORG_ID", "OPENAI_PROJECT_ID",
)
_ENV_KEY = re.compile(r"^[A-Z_][A-Z0-9_]{0,127}$")
_BLOCKED_PROVIDER_ENV_PREFIXES = ("AGENTPORTER_", "OPENAI_TUNNEL_", "MCP_", "GITHUB_TOKEN")
_CHECK_FLAGS = (
    "-c", "sandbox_workspace_write.network_access=false",
    "-c", "sandbox_workspace_write.writable_roots=[]",
    "-c", "sandbox_workspace_write.exclude_slash_tmp=true",
    "-c", "sandbox_workspace_write.exclude_tmpdir_env_var=true",
)


def _toml_value(value):
    if isinstance(value, str):
        return json.dumps(value)
    if isinstance(value, bool):
        return str(value).lower()
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return str(value)
    if isinstance(value, list):
        return "[" + ", ".join(_toml_value(item) for item in value) + "]"
    if isinstance(value, dict):
        return "{ " + ", ".join(
            f"{json.dumps(str(k))} = {_toml_value(v)}" for k, v in value.items()
        ) + " }"
    raise ValueError("Unsupported Codex model-provider setting type")


def _clean_profile_data(source_home: Path) -> tuple[str, set[str]]:
    config_path = source_home / "config.toml"
    if not config_path.is_file():
        return "", set()
    try:
        data = tomllib.loads(config_path.read_text(encoding="utf-8"))
    except (ValueError, OSError) as exc:
        raise RuntimeError("Codex profile config cannot be safely parsed") from exc
    # A selected Codex profile can silently replace routing settings if
    # dropped. Refuse rather than silently run under a different provider.
    if data.get("profile"):
        raise RuntimeError("Selected Codex profiles require explicit routing resolution")
    # Authentication restrictions are policy, not optional preferences.
    # Preserve known restrictions; reject unknown forced_* settings rather
    # than silently dropping constraints added by future Codex releases.
    unknown_forced = {key for key in data if key.startswith("forced_")} - set(_ROOT_KEYS)
    if unknown_forced:
        raise RuntimeError("Unsupported Codex account constraints: " + ", ".join(sorted(unknown_forced)))
    for key in ("forced_login_method", "forced_chatgpt_workspace_id"):
        if key in data and (not isinstance(data[key], str) or not data[key].strip()):
            raise RuntimeError(f"Invalid Codex account constraint: {key}")
    lines = []
    for key in _ROOT_KEYS:
        if key in data:
            lines.append(f"{key} = {_toml_value(data[key])}")
    provider_env = set()
    providers = data.get("model_providers", {})
    if not isinstance(providers, dict):
        raise RuntimeError("Codex model_providers must be a table")
    for name, fields in providers.items():
        if not isinstance(name, str) or not isinstance(fields, dict):
            raise RuntimeError("Invalid Codex model provider")
        unexpected = set(fields) - set(_PROVIDER_KEYS)
        if unexpected:
            raise RuntimeError("Unsupported Codex model-provider keys: " + ", ".join(sorted(unexpected)))
        lines.append(f"[model_providers.{json.dumps(name)}]")
        for key in _PROVIDER_KEYS:
            if key not in fields:
                continue
            value = fields[key]
            lines.append(f"{key} = {_toml_value(value)}")
            if key == "env_key":
                if not isinstance(value, str) or not _ENV_KEY.fullmatch(value) or value.startswith(_BLOCKED_PROVIDER_ENV_PREFIXES):
                    raise RuntimeError("Unsafe Codex model-provider env_key")
                provider_env.add(value)
            if key == "env_http_headers":
                if not isinstance(value, dict):
                    raise RuntimeError("Invalid Codex provider env_http_headers")
                for env_name in value.values():
                    if not isinstance(env_name, str) or not _ENV_KEY.fullmatch(env_name) or env_name.startswith(_BLOCKED_PROVIDER_ENV_PREFIXES):
                        raise RuntimeError("Unsafe Codex model-provider header environment variable")
                    provider_env.add(env_name)
    return "\n".join(lines) + "\n", provider_env


def _reject_project_overrides(workspace: Path) -> None:
    # Project configurations can add MCP servers after the user config layer.
    # The empty mcp_servers override does not clear existing servers.
    for path in (
        workspace / ".codex" / "config.toml",
        workspace / ".mcp.json",
        workspace / ".agents" / "plugins" / "marketplace.json",
    ):
        if path.exists() or path.is_symlink():
            raise RuntimeError(
                "Delegated Codex refuses project-level MCP/plugin configuration; "
                "use an isolated inspection checkout without these files"
            )


def safe_launcher_environment(source_home: str) -> dict[str, str]:
    # Sanitize the initial Python subprocess, not just its subsequent Codex
    # child. Preserve only explicitly referenced provider authentication keys.
    _, provider_env = _clean_profile_data(Path(source_home).expanduser().resolve())
    return {
        name: os.environ[name] for name in (*_ALLOWED_ENV, *sorted(provider_env))
        if name in os.environ
    }


def _safe_environment(profile: Path, provider_env: set[str]) -> dict[str, str]:
    env = {
        name: os.environ[name] for name in (*_ALLOWED_ENV, *sorted(provider_env))
        if name in os.environ
    }
    env["CODEX_HOME"] = str(profile)
    return env


def _validate_mcp_roster(executable: str, cwd: Path, env: dict[str, str]) -> None:
    try:
        result = subprocess.run(
            [executable, *_CHECK_FLAGS, "mcp", "list", "--json"],
            cwd=cwd, env=env, text=True, capture_output=True, timeout=15,
            check=True,
        )
        listed = json.loads(result.stdout)
    except (subprocess.SubprocessError, OSError, ValueError) as exc:
        raise RuntimeError("Cannot verify isolated Codex MCP roster") from exc
    if not isinstance(listed, list) or any(
        not isinstance(server, dict) or server.get("enabled", True)
        for server in listed
    ):
        raise RuntimeError("Isolated Codex profile contains enabled MCP tools")


def run(source_home: str, workspace: str, command: list[str]) -> int:
    if not command or not Path(command[0]).is_absolute():
        raise RuntimeError("Codex executable must be an absolute path")
    if len(command) < 2 or command[1] != "exec":
        raise RuntimeError("Only the Codex exec subcommand may run")
    workspace_path = Path(workspace).resolve(strict=True)
    source = Path(source_home).expanduser().resolve()
    _reject_project_overrides(workspace_path)
    clean_config, provider_env = _clean_profile_data(source)
    with tempfile.TemporaryDirectory(prefix="agentporter-codex-") as home:
        profile = Path(home)
        os.chmod(profile, 0o700)
        (profile / "config.toml").write_text(clean_config, encoding="utf-8")
        os.chmod(profile / "config.toml", 0o600)
        auth = source / "auth.json"
        if auth.is_file():
            info = auth.stat()
            if info.st_uid != os.getuid() or info.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
                raise RuntimeError("Unsafe Codex auth.json ownership or permissions")
            (profile / "auth.json").symlink_to(auth)
        env = _safe_environment(profile, provider_env)
        _validate_mcp_roster(command[0], workspace_path, env)
        result = subprocess.run(
            [command[0], command[1], *_CHECK_FLAGS, *command[2:]],
            cwd=workspace_path, env=env, check=False,
        )
        return result.returncode


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-home", required=True)
    parser.add_argument("--workspace", required=True)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args(argv)
    command = args.command
    if command and command[0] == "--":
        command = command[1:]
    try:
        return run(args.source_home, args.workspace, command)
    except (RuntimeError, ValueError, OSError) as exc:
        print(f"Isolated Codex launch refused: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
