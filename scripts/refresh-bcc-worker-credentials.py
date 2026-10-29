#!/usr/bin/python3
"""Operator-only credential freshness and scoped refresh for confined BCC.

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

OWNER = "yeli"
ACCOUNT = "agentporter-bcc-worker"
DATA = Path("/var/lib/agentporter-bcc-worker/staging/bcc-stage-20261027-03/credentials")
STAGING = Path("/var/lib/agentporter-bcc-stage-operator/credential-refresh")
SOURCES = {
    "jax": {
        ".codex/auth.json": "/home/yeli/.codex/auth.json",
        ".codex/config.toml": "/home/yeli/.codex/config.toml",
    },
    "liz": {
        ".codex/auth.json": "/home/yeli/.codex-liz/auth.json",
        ".codex/config.toml": "/home/yeli/.codex-liz/config.toml",
    },
    "prof": {
        ".codex/auth.json": "/home/yeli/.codex-prof/auth.json",
        ".codex/config.toml": "/home/yeli/.codex-prof/config.toml",
    },
    "ming": {".claude/.credentials.json": "/home/yeli/.claude/.credentials.json"},
    "phil": {".copilot-phil/config.json": "/home/yeli/.copilot-phil/config.json"},
    "wei": {".config/opencode/wei-key": "/home/yeli/.config/opencode/wei-key"},
    "argie": {
        ".gemini/antigravity-cli/antigravity-oauth-token":
        "/home/yeli/.gemini/antigravity-cli/antigravity-oauth-token"
    },
}
MAX_BYTES = 1024 * 1024


def _trusted_installed_program():
    path = Path(__file__)
    if path.is_symlink() or not path.is_absolute():
        raise PermissionError("Operator helper must be an installed absolute regular file")
    actual = path.resolve(strict=True)
    if not (actual == Path("/usr/local/libexec/agentporter-bcc-refresh-credentials.py")):
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
    staging_dir = staging_dir if staging_dir is not None else STAGING
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
        print(f"{agent} owner_provider_route: missing_local_config")
        return
    content = _validated_secret(path, pwd.getpwnam(OWNER).pw_uid,
                                allow_absent=False, allow_public_read=True)
    try:
        data = tomllib.loads(content.decode("utf-8"))
        provider = data.get("model_provider", "openai")
        table = data.get("model_providers", {}).get(provider, {})
        url = table.get("base_url") or data.get("openai_base_url")
        if url is None:
            print(f"{agent} owner_provider_route: {provider} / default")
            return
        parts = urlsplit(url)
        if (parts.scheme not in {"https", "http"} or not parts.hostname
                or parts.username or parts.password):
            print(f"{agent} owner_provider_route: custom / unsupported format")
            return
        host = parts.hostname
        try:
            ip = ipaddress.ip_address(host)
            classification = "public" if ip.is_global else "private_or_loopback"
        except ValueError:
            classification = "hostname_check_needed"
            if host.lower() in {"localhost", "host.docker.internal"} or host.endswith((".local", ".internal")):
                classification = "private_or_loopback"
        print(f"{agent} owner_provider_route: {provider} {parts.scheme}://{host}:{parts.port or (443 if parts.scheme == 'https' else 80)} ({classification})")
    except (UnicodeError, ValueError, AttributeError, TypeError):
        print(f"{agent} owner_provider_route: cannot_parse safely")


def _prepare_staging():
        parent_fd = _pinned_directory(STAGING.parent, 0)
        try:
            try: os.mkdir(STAGING.name, 0o700, dir_fd=parent_fd)
            except FileExistsError: pass
        finally: os.close(parent_fd)
        checked_fd = _pinned_directory(STAGING, 0)
        os.close(checked_fd)


def _run(*, apply: bool, agents: list[str]):
    source_uid = pwd.getpwnam(OWNER).pw_uid
    destination = pwd.getpwnam(ACCOUNT)
    if os.geteuid() != 0:
        raise PermissionError("Refresh requires root via installed trusted helper")
    if not DATA.is_dir() or DATA.is_symlink():
        raise PermissionError("Isolated worker credential directory not installed")
    if (DATA.parent.stat().st_uid not in {0, destination.pw_uid} or DATA.parent.stat().st_mode & 0o022
            or DATA.stat().st_uid != destination.pw_uid or DATA.stat().st_mode & 0o077):
        raise PermissionError("Development credential storage violates owner/mode boundary")
    if apply: _prepare_staging()
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


def _jax_direct_openai(*, apply):
    import json, re
    destination = pwd.getpwnam(ACCOUNT)
    auth = _validated_secret(DATA / 'jax/.codex/auth.json', destination.pw_uid, allow_absent=False)
    document = json.loads(auth)
    tokens = document.get('tokens', {})
    if (document.get('auth_mode') not in (None,'chatgpt') or document.get('OPENAI_API_KEY')
            or not isinstance(tokens,dict) or not tokens.get('access_token')):
        raise PermissionError('Direct Jax repair requires its existing ChatGPT OAuth account, not an API billing key')
    target = DATA / 'jax/.codex/config.toml'
    content = _validated_secret(target,destination.pw_uid,allow_absent=False)
    text = content.decode('utf-8')
    parsed = tomllib.loads(text)
    provider = parsed.get('model_provider','openai')
    if provider == 'openai':
        print('jax confined_route: already_openai'); return
    if provider != 'headroom':
        raise PermissionError('Unknown Jax provider route; preserve configuration')
    route = parsed.get('model_providers',{}).get('headroom',{}).get('base_url','')
    if urlsplit(route).hostname not in {'127.0.0.1','localhost','::1'}:
        raise PermissionError('Expected the diagnosed loopback Headroom route')
    direct = parsed.get('model_providers',{}).get('openai',{})
    if direct.get('base_url'):
        raise PermissionError('Custom OpenAI route requires separate review')
    lines = []; table = False; replaced = False
    for line in text.splitlines():
        if line.lstrip().startswith('['): table = True
        if not table and re.match(r'^\s*model_provider\s*=',line):
            lines.append('model_provider = "openai"'); replaced = True
        elif not table and re.match(r'^\s*openai_base_url\s*=',line):
            continue
        else: lines.append(line)
    if not replaced: lines.insert(0,'model_provider = "openai"')
    updated = ('\n'.join(lines)+'\n').encode()
    require_data = tomllib.loads(updated.decode())
    if require_data.get('model_provider') != 'openai' or 'openai_base_url' in require_data:
        raise PermissionError('Could not safely prepare direct Jax route')
    if apply:
        _install_secret(target,updated,destination.pw_uid,destination.pw_gid)
        print('jax confined_route: repaired_to_direct_openai (owner profile unchanged)')
    else:
        print('jax confined_route: headroom_loopback -> direct_openai (plan only)')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--direct-openai-jax", action="store_true", help="Explicitly replace only the confined Jax loopback Headroom route with its existing ChatGPT OAuth account on direct OpenAI")
    parser.add_argument("--routes", action="store_true", help="Report Codex provider hostnames, not credentials")
    parser.add_argument("--agents", default=",".join(SOURCES))
    args = parser.parse_args()
    if args.check == args.apply:
        parser.error("Choose exactly one of --check or --apply")
    if not sys.flags.isolated or Path(sys.executable).resolve() != Path("/opt/agentporter-bcc/releases/bcc-stage-20261028-08/venv/bin/python").resolve():
        raise SystemExit("Use the release-08 Python with -I -S to invoke the installed helper")
    _trusted_installed_program()
    if (pwd.getpwnam(OWNER).pw_uid,pwd.getpwnam(ACCOUNT).pw_uid,pwd.getpwnam(ACCOUNT).pw_gid) != (2056259175,997,997):
        raise PermissionError("Unexpected BCC account identities")
    agents = args.agents.split(",")
    if not agents or any(name not in SOURCES for name in agents):
        parser.error("Unknown agent in --agents")
    _run(apply=args.apply, agents=agents)
    if args.direct_openai_jax:
        if 'jax' not in agents: parser.error('Direct Jax repair requires jax in --agents')
        _jax_direct_openai(apply=args.apply)
    if args.routes:
        for agent in agents:
            _describe_codex_route(agent)


if __name__ == "__main__":
    main()
