"""Host tool discovery and the small tool surface exposed to sandboxes."""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path


TOOLING_COMMANDS = (
    "quarto", "R", "Rscript", "pandoc", "rg", "fd", "fzf", "bat", "jq",
    "yq", "git", "delta", "shellcheck", "shfmt", "hyperfine", "python3",
    "uv", "bwrap", "patch", "rsync", "curl", "lsof", "ss", "findmnt",
    "sha256sum", "rtk",
)
TOOL_ALIASES = {"fd": ("fd", "fdfind"), "bat": ("bat", "batcat")}

# Only these host-local tools are candidates for read-only executable mounts.
# The host PATH and home directory are never passed through wholesale.
HOST_TOOL_BINDINGS = (
    "quarto", "rtk", "eza", "tree", "yq", "delta", "uv", "duckdb",
    "watchexec", "entr", "htop", "btop", "strace",
)


def resolve_tool(name: str) -> str | None:
    """Resolve a command, including stable Debian naming aliases."""
    for candidate in TOOL_ALIASES.get(name, (name,)):
        path = shutil.which(candidate)
        if path:
            return path
    return None


def tool_inventory() -> list[dict[str, str | None]]:
    """Return bounded host-side diagnostics for the supported tool surface."""
    return [
        {"name": name, "path": (path := resolve_tool(name)),
         "status": "OK" if path else "MISSING"}
        for name in TOOLING_COMMANDS
    ]


def tool_version(path: str) -> str:
    """Read one compact version line without allowing a tool to block doctor."""
    try:
        result = subprocess.run(
            [path, "--version"], capture_output=True, text=True, timeout=3, check=False
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return f"unavailable ({type(exc).__name__})"
    output = (result.stdout or result.stderr).strip().splitlines()
    return output[0][:160] if output else f"exit {result.returncode}"


def _add_host_binding(args: list[str], name: str, source: str) -> str:
    resolved = Path(os.path.realpath(source))
    if name == "quarto" and resolved.parent.name == "bin":
        mountpoint = "/opt/agentporter/quarto"
        args.extend(["--ro-bind", str(resolved.parent.parent), mountpoint])
        return f"{mountpoint}/bin/{resolved.name}"
    mountpoint = f"/opt/agentporter/host-tools/{name}"
    args.extend(["--ro-bind", str(resolved), mountpoint])
    return mountpoint


def add_tooling_mounts(args: list[str]) -> None:
    """Add supported host tools and aliases to a bwrap argument list."""
    args.extend([
        "--dir", "/opt", "--dir", "/opt/agentporter",
        "--dir", "/opt/agentporter/bin", "--dir", "/opt/agentporter/host-tools",
    ])
    exposed: dict[str, str] = {}
    for name in HOST_TOOL_BINDINGS:
        source = resolve_tool(name)
        if source and not os.path.realpath(source).startswith(("/usr/", "/bin/")):
            exposed[name] = _add_host_binding(args, name, source)

    for name in TOOL_ALIASES:
        source = resolve_tool(name)
        if not source:
            continue
        source_path = os.path.realpath(source)
        if source_path.startswith(("/usr/", "/bin/")):
            exposed[name] = source_path
        elif name not in exposed:
            exposed[name] = _add_host_binding(args, name, source)

    for name, source in exposed.items():
        destination = f"/opt/agentporter/bin/{name}"
        if source != destination:
            args.extend(["--symlink", source, destination])
