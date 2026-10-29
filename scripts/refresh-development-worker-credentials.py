#!/usr/bin/python3
"""Operator-only credential freshness and scoped refresh for confined A7Dev.

Installed as a trusted root-owned copy outside all delegated workspaces.
Never prints or emits credentials, their fingerprints, or source contents.
Use --check for read-only freshness, or --apply --agents AGENT[,AGENT].
No service restart is required; new confined jobs pin the updated credential.
"""
from __future__ import annotations

import argparse
import hashlib
import hmac
import os
from pathlib import Path
import pwd
import stat
import sys
import secrets
import tomllib
from urllib.parse import urlsplit
import ipaddress

OWNER = "operator"
ACCOUNT = "agentporter-dev"
DATA = Path("/var/lib/agentporter-dev/credentials")
SOURCES = {
    "jax": {
        ".codex/auth.json": "/home/operator/.codex/auth.json",
        ".codex/config.toml": "/home/operator/.codex/config.toml",
    },
    "liz": {
        ".codex/auth.json": "/home/operator/.codex-liz/auth.json",
        ".codex/config.toml": "/home/operator/.codex-liz/config.toml",
    },
    "prof": {
        ".codex/auth.json": "/home/operator/.codex-prof/auth.json",
        ".codex/config.toml": "/home/operator/.codex-prof/config.toml",
    },
    "ming": {".claude/.credentials.json": "/home/operator/.claude/.credentials.json"},
    "phil": {".copilot-phil/config.json": "/home/operator/.copilot-phil/config.json"},
    "wei": {".config/opencode/wei-key": "/home/operator/.config/opencode/go-key"},
    "argie": {
        ".gemini/antigravity-cli/antigravity-oauth-token":
        "/home/operator/.gemini/antigravity-cli/antigravity-oauth-token"
    },
}
MAX_BYTES = 1024 * 1024


def _trusted_installed_program():
    path = Path(__file__)
    if path.is_symlink() or not path.is_absolute():
        raise PermissionError("Operator helper must be an installed absolute regular file")
    actual = path.resolve(strict=True)
    if not (actual == Path("/usr/local/libexec/agentporter/refresh-development-worker-credentials.py")
            or actual == Path("/usr/local/libexec/refresh-development-worker-credentials.py")):
        raise PermissionError("Install this helper outside all writable workspaces")
    for component in (actual, *actual.parents):
        info = component.lstat()
        if stat.S_ISLNK(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise PermissionError("Operator helper and all ancestors require trusted root ownership and modes")
    if not stat.S_ISREG(actual.stat().st_mode):
        raise PermissionError("Operator helper must be regular")


def _pinned_directory(path: Path, owner_uid: int) -> int:
    """Walk every component via O_NOFOLLOW; never trust a checked pathname."""
    if not path.is_absolute():
        raise PermissionError("Credential directory must be absolute")
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for component in path.parts[1:]:
            parent = os.fstat(fd)
            if not stat.S_ISDIR(parent.st_mode):
                raise PermissionError("Invalid credential directory ancestor")
            if parent.st_uid not in {0, owner_uid}:
                raise PermissionError("Credential directory ancestor owned by third party")
            if parent.st_mode & 0o022 and not (
                    parent.st_uid == 0 and parent.st_mode & stat.S_ISVTX):
                raise PermissionError("Untrusted writable credential directory ancestor")
            next_fd = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                              dir_fd=fd)
            os.close(fd)
            fd = next_fd
        info = os.fstat(fd)
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid not in {0, owner_uid}
                or info.st_mode & 0o022):
            raise PermissionError("Untrusted credential directory")
        result, fd = fd, -1
        return result
    finally:
        if fd >= 0:
            os.close(fd)


def _is_private_destination_dir(path: Path, uid: int) -> None:
    """Validate the opened destination, never follow a checked pathname."""
    fd = _pinned_directory(path, uid)
    try:
        info = os.fstat(fd)
        if info.st_uid != uid or info.st_mode & 0o077:
            raise PermissionError("Destination must be a private service directory")
    finally:
        os.close(fd)


def _validated_secret(path: Path, uid: int, *, allow_absent: bool,
                      allow_public_read: bool = False):
    if not path.is_absolute():
        raise PermissionError("Credential path must be absolute")
    parent_fd = _pinned_directory(path.parent, uid)
    try:
        try:
            fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                         dir_fd=parent_fd)
        except FileNotFoundError:
            if allow_absent:
                return None
            raise
        try:
            # Check the *opened descriptor*, including metadata that could
            # change after a previous stat or pathname validation.
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != uid
                    or info.st_mode & (0o022 if allow_public_read else 0o077)
                    or not 1 <= info.st_size <= MAX_BYTES):
                raise PermissionError("Invalid credential owner, mode, or size")
            content = os.read(fd, MAX_BYTES + 1)
            after = os.fstat(fd)
            if (not content or len(content) != info.st_size or len(content) > MAX_BYTES
                    or (info.st_dev, info.st_ino, info.st_size, info.st_mode, info.st_uid, info.st_mtime_ns, info.st_ctime_ns)
                    != (after.st_dev, after.st_ino, after.st_size, after.st_mode, after.st_uid, after.st_mtime_ns, after.st_ctime_ns)):
                raise PermissionError("Invalid credential content size")
            return content
        finally:
            os.close(fd)
    finally:
        os.close(parent_fd)


def _install_secret(path: Path, content: bytes, uid: int, gid: int,
                    *, staging_dir: Path | None = None, staging_uid: int = 0):
    """Stage in a non-service-writable directory and rename by pinned fds.

    The runtime's destination directory is dev-owned by design, so it can
    replace its OWN credential later. This helper must never allow it to
    redirect a privileged write through an ancestor or staged file.
    """
    if not content or len(content) > MAX_BYTES:
        raise PermissionError("Credential content invalid")
    staging_dir = staging_dir if staging_dir is not None else DATA.parent
    source_fd = _pinned_directory(staging_dir, staging_uid)
    dest_fd = None
    temp_name = ".credential-refresh-" + secrets.token_hex(16)
    created = False
    try:
        source_info = os.fstat(source_fd)
        if (source_info.st_uid != staging_uid or source_info.st_mode & 0o022):
            raise PermissionError("Staging parent is not operator-controlled")
        dest_fd = _pinned_directory(path.parent, uid)
        target = os.fstat(dest_fd)
        if target.st_uid != uid or target.st_mode & 0o077:
            raise PermissionError("Destination must be a private service directory")
        fd = os.open(temp_name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                     0o600, dir_fd=source_fd)
        created = True
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "wb", closefd=False) as writer:
                writer.write(content)
                writer.flush()
                os.fsync(fd)
            os.fchown(fd, uid, gid)
            os.fsync(fd)
        finally:
            os.close(fd)
        os.rename(temp_name, path.name, src_dir_fd=source_fd, dst_dir_fd=dest_fd)
        created = False
    finally:
        if created:
            os.unlink(temp_name, dir_fd=source_fd)
        if dest_fd is not None:
            os.close(dest_fd)
        os.close(source_fd)


def _describe_codex_route(agent: str):
    """Expose only provider and transport authority, never URLs or tokens."""
    route_file = SOURCES.get(agent, {}).get(".codex/config.toml")
    if not route_file:
        return
    path = Path(route_file)
    if not path.exists():
        print(f"{agent} provider_route: missing_local_config")
        return
    content = _validated_secret(path, pwd.getpwnam(OWNER).pw_uid,
                                allow_absent=False, allow_public_read=True)
    try:
        data = tomllib.loads(content.decode("utf-8"))
        provider = data.get("model_provider", "openai")
        table = data.get("model_providers", {}).get(provider, {})
        url = table.get("base_url") or data.get("openai_base_url")
        if url is None:
            print(f"{agent} provider_route: {provider} / default")
            return
        parts = urlsplit(url)
        if (parts.scheme not in {"https", "http"} or not parts.hostname
                or parts.username or parts.password):
            print(f"{agent} provider_route: custom / unsupported format")
            return
        host = parts.hostname
        try:
            ip = ipaddress.ip_address(host)
            classification = "public" if ip.is_global else "private_or_loopback"
        except ValueError:
            classification = "hostname_check_needed"
            if host.lower() in {"localhost", "host.docker.internal"} or host.endswith((".local", ".internal")):
                classification = "private_or_loopback"
        print(f"{agent} provider_route: {provider} {parts.scheme}://{host}:{parts.port or (443 if parts.scheme == 'https' else 80)} ({classification})")
    except (UnicodeError, ValueError, AttributeError, TypeError):
        print(f"{agent} provider_route: cannot_parse safely")


def _run(*, apply: bool, agents: list[str]):
    source_uid = pwd.getpwnam(OWNER).pw_uid
    destination = pwd.getpwnam(ACCOUNT)
    if os.geteuid() != 0:
        raise PermissionError("Refresh requires root via installed trusted helper")
    if not DATA.is_dir() or DATA.is_symlink():
        raise PermissionError("Isolated worker credential directory not installed")
    if (DATA.parent.stat().st_uid != 0 or DATA.parent.stat().st_mode & 0o022
            or DATA.stat().st_uid != destination.pw_uid or DATA.stat().st_mode & 0o077):
        raise PermissionError("Development credential storage violates owner/mode boundary")
    for agent in agents:
        if agent not in SOURCES:
            raise PermissionError("Unknown agent identity")
        for relative, original in SOURCES[agent].items():
            target = DATA / agent / relative
            source = Path(original)
            _is_private_destination_dir(target.parent, destination.pw_uid)
            incoming = _validated_secret(source, source_uid, allow_absent=True, allow_public_read=relative.endswith("/config.toml"))
            deployed = _validated_secret(target, destination.pw_uid, allow_absent=True)
            if relative.endswith("/config.toml") and apply:
                print(f"{agent} {relative}: provider_config_not_auto_refreshed (review approved route)")
            elif incoming is None:
                print(f"{agent} {relative}: source_missing (renew/login on owner account)")
            elif deployed is not None and hmac.compare_digest(
                    hashlib.sha256(incoming).digest(), hashlib.sha256(deployed).digest()):
                print(f"{agent} {relative}: current")
            elif apply:
                _install_secret(target, incoming, destination.pw_uid, destination.pw_gid)
                print(f"{agent} {relative}: refreshed")
            else:
                print(f"{agent} {relative}: stale_or_absent")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--routes", action="store_true", help="Report Codex provider hostnames, not credentials")
    parser.add_argument("--agents", default=",".join(SOURCES))
    args = parser.parse_args()
    if args.check == args.apply:
        parser.error("Choose exactly one of --check or --apply")
    if not sys.flags.isolated or Path(sys.executable).resolve() != Path("/usr/bin/python3").resolve():
        raise SystemExit("Use /usr/bin/python3 -I to invoke the installed helper")
    _trusted_installed_program()
    agents = args.agents.split(",")
    if not agents or any(name not in SOURCES for name in agents):
        parser.error("Unknown agent in --agents")
    _run(apply=args.apply, agents=agents)
    if args.routes:
        for agent in agents:
            _describe_codex_route(agent)


if __name__ == "__main__":
    main()
