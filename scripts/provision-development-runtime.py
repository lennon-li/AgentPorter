#!/usr/bin/python3
"""Asgard-only, development-only provisioning. Default: validate and print plan.

Legacy operator utility. Root execution is disabled following the security audit.
Prepare release artifacts unprivileged; privileged installation must use the
separate, reviewed data-only installer, never this mutable repository program.
"""
from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import pwd
import shutil
import socket
import stat
import subprocess
import sys
import urllib.request
import time

if os.geteuid() == 0:
    raise SystemExit("Unsafe legacy root provisioning is disabled. Build a candidate unprivileged and use the reviewed immutable artifact installer.")

try:
    import yaml  # distro python3-yaml, never the repository virtualenv
except ImportError:
    raise SystemExit('Prerequisite missing: install distro python3-yaml before provisioning.')

REPO = Path('/home/yeli/agent-work/agentporter-dev')
STAGE = Path('/tmp/agentporter-development-asgard/config')
INSTALL = Path('/opt/agentporter-development')
DATA = Path('/var/lib/agentporter-dev')
ACCOUNT = 'agentporter-dev'
OBSIDIAN = Path('/home/yeli/repos/obsidian')
UNIT_NAME = 'agentporter-development.service'
SYSTEM_UNIT = Path('/etc/systemd/system') / UNIT_NAME
AGENTS = ('jax', 'liz', 'prof', 'phil', 'wei', 'ming', 'argie')
WORKSPACES = {
    'm3-poc': '/home/yeli/m3-agent-poc', 'insider': '/home/yeli/repos/insider',
    'PAGe': '/home/yeli/repos/PAGe', 'm3': '/home/yeli/repos/m3',
    'obsidian': '/home/yeli/repos/obsidian', 'shiny': '/home/yeli/repos/shiny',
    'cranary': '/home/yeli/repos/cranary', 'agentporter-dev': str(REPO),
}
CREDENTIALS = {
    'jax': {'.codex/auth.json': '/home/yeli/.codex/auth.json', '.codex/config.toml': '/home/yeli/.codex/config.toml'},
    'liz': {'.codex/auth.json': '/home/yeli/.codex-liz/auth.json', '.codex/config.toml': '/home/yeli/.codex-liz/config.toml'},
    'prof': {'.codex/auth.json': '/home/yeli/.codex-prof/auth.json', '.codex/config.toml': '/home/yeli/.codex-prof/config.toml'},
    'ming': {'.claude/.credentials.json': '/home/yeli/.claude/.credentials.json'},
    'phil': {'.copilot-phil/config.json': '/home/yeli/.copilot-phil/config.json'},
    'wei': {'.config/opencode/wei-key': '/home/yeli/.config/opencode/go-key'},
    'argie': {'.gemini/antigravity-cli/antigravity-oauth-token': '/home/yeli/.gemini/antigravity-cli/antigravity-oauth-token'},
}
MASK_DIRS = {'.git', '.ssh', '.aws', '.codex', '.agents', '.development', '.claude', '.copilot',
             '.copilot-phil', '.opencode', '.github-copilot', '.antigravitycli', '.gemini', 'runtime'}


def run(argv, *, check=True, env=None):
    return subprocess.run([str(x) for x in argv], check=check, text=True,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          stdin=subprocess.DEVNULL, env=env or {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C.UTF-8'})


def document(path):
    no_symlink(path)
    value = yaml.safe_load(path.read_text())
    if not isinstance(value, dict):
        raise ValueError(f'Expected YAML mapping: {path}')
    return value


def no_symlink(path):
    path = Path(path)
    for component in (path, *path.parents):
        if component.is_symlink():
            raise ValueError(f'Refusing symlinked destination/input: {component}')


def validate_inputs():
    owner = pwd.getpwnam('yeli')
    if owner.pw_uid == 0:
        raise ValueError('Production/source owner must not be root')
    if Path(__file__).resolve().parent.parent != REPO:
        raise ValueError(f'This operator helper must be run from {REPO}/scripts')
    no_symlink(STAGE)
    config = document(STAGE / 'config.yaml')
    server = config.get('server', {})
    if server.get('host') != '127.0.0.1' or server.get('port') != 8876 or config.get('sandbox', {}).get('network') is not False:
        raise ValueError('Staged gateway must use loopback port 8876 and offline generic commands')
    runtime = document(STAGE / 'development-runtime.yaml')
    if (runtime.get('profile'), runtime.get('enabled'), runtime.get('gateway_user'), runtime.get('production_uid')) != ('development', True, ACCOUNT, owner.pw_uid):
        raise ValueError('Staged runtime is not the approved separate-UID development profile')
    workers = runtime.get('workers', {})
    if set(workers) != set(AGENTS):
        raise ValueError('Staged runtime must explicitly name all seven workers')
    for name, spec in workers.items():
        if spec.get('credentials') != CREDENTIALS[name]:
            raise ValueError(f'Unexpected credential sources for {name}; no alternate credentials are allowed')
        for source in spec['credentials'].values():
            source = Path(source)
            if source.exists():
                no_symlink(source)
                if not source.is_file() or source.stat().st_uid != owner.pw_uid:
                    raise ValueError(f'Credential source is not a source-user regular file: {source}')
        executable = Path(spec.get('executable', ''))
        if not executable.is_absolute() or not str(executable).startswith('/home/yeli/'):
            raise ValueError(f'Unexpected worker executable source: {name}')
        if executable.exists() and (not executable.is_file() or not os.access(executable, os.X_OK)):
            raise ValueError(f'Worker executable is not executable: {name}')
    workspaces = document(STAGE / 'workspaces.yaml')
    rows = workspaces.get('workspaces', {})
    if set(rows) != set(WORKSPACES):
        raise ValueError('Staged workspace registry must match the eight approved development workspaces')
    for key, spec in rows.items():
        expected = Path(WORKSPACES[key]).resolve(strict=True)
        if Path(spec['path']).resolve(strict=True) != expected or not expected.is_dir():
            raise ValueError(f'Unexpected workspace: {key}')
        if spec.get('allow_agent_dispatch') is not True:
            raise ValueError(f'Delegation not authorized in workspace: {key}')
    interpreter = (REPO / '.venv/bin/python').resolve(strict=True)
    if not str(interpreter).startswith('/home/yeli/.local/share/uv/python/cpython-3.13.'):
        raise ValueError('Unexpected virtualenv interpreter; review the local offline snapshot plan')
    if not (REPO / '.venv/lib/python3.13/site-packages').is_dir():
        raise ValueError('Missing current Python 3.13 virtualenv dependencies')
    for tool in ('setfacl', 'getfacl', 'useradd', 'runuser', 'systemctl'):
        if not shutil.which(tool):
            raise ValueError(f'Prerequisite missing: {tool} (setfacl/getfacl are provided by distro acl)')
    if not Path('/usr/bin/bwrap').is_file():
        raise ValueError('Prerequisite missing: /usr/bin/bwrap')
    for destination in (INSTALL, DATA, SYSTEM_UNIT):
        no_symlink(destination)
        if destination.exists() and destination.stat().st_uid != 0:
            raise ValueError(f'Existing privileged destination must be root-owned: {destination}')
    try:
        account = pwd.getpwnam(ACCOUNT)
    except KeyError:
        account = None
    if account and (account.pw_uid in (0, owner.pw_uid) or account.pw_dir != str(DATA / 'home')):
        raise ValueError('Existing development account has an unsafe UID or unexpected HOME')
    if account and (account.pw_gid == 0 or set(os.getgrouplist(ACCOUNT, account.pw_gid)) != {account.pw_gid}):
        raise ValueError('Development account must have only its private primary group; no home/sudo/production group grants')
    if SYSTEM_UNIT.exists() and 'User=agentporter-dev\n' not in SYSTEM_UNIT.read_text():
        raise ValueError('Refusing to replace an existing system development unit with a different User')
    return config, runtime, workspaces, interpreter.parent.parent, owner


def copy_tree(source, target, *, ignore=None):
    """Copy links as links, then reject links escaping the copied tree."""
    shutil.copytree(source, target, symlinks=True, ignore=ignore)
    base = target.resolve()
    for root, directories, files in os.walk(target, followlinks=False):
        for name in directories + files:
            path = Path(root) / name
            if path.is_symlink() and not path.resolve().is_relative_to(base):
                raise ValueError(f'Installed snapshot contains an external symlink: {path.relative_to(base)}')


def immutable_tree(root):
    for current, directories, files in os.walk(root, followlinks=False):
        for name in files:
            path = Path(current) / name
            if path.is_symlink():
                continue
            os.chown(path, 0, 0)
            os.chmod(path, 0o555 if path.stat().st_mode & 0o111 else 0o444)
        os.chown(current, 0, 0)
        os.chmod(current, 0o555)


def atomic_text(path, contents, mode=0o600, uid=None, gid=None):
    no_symlink(path)
    temporary = path.with_name(path.name + '.provision-new')
    no_symlink(temporary)
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    try:
        if uid is not None or gid is not None:
            os.fchown(fd, -1 if uid is None else uid, -1 if gid is None else gid)
        with os.fdopen(fd, 'w') as stream:
            stream.write(contents)
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


def private_dir(path, uid, gid):
    no_symlink(path)
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chown(path, uid, gid)
    os.chmod(path, 0o700)


def stage_shared_obsidian(source: Path, destination: Path, *, approved_files=None) -> dict:
    """Copy an explicit, bounded public skills/policy catalogue as inert data.

    The operator creates the immutable, root-owned release snapshot. No user
    executable, plugin hook, credentials, or writable directory is mounted from
    the live Obsidian checkout. Files are opened through pinned directory fds
    with O_NOFOLLOW; supplied symlinks and private files fail closed.
    """
    import stat as _stat
    scopes = (
        "AgentSystem/agent-memory/skills",
        "AgentSystem/agent-memory/boot",
        "AgentSystem/agent-memory/policies",
        "AgentSystem/agent-memory/loaders",
        "Toolbox/claude-skills",
        "tools",
    )
    allowed = {".md", ".json", ".yaml", ".yml", ".toml", ".txt",
               ".py", ".sh", ".jsonl", ".tmpl", ".ps1"}
    selected = {"tools/agent-tool-policy.json", "tools/AGENT_TOOL_HANDOFF.md",
                "tools/bin/run-quiet"}
    count = 0
    total = 0
    digests = {}
    approved_directories = ({str(parent) for name in approved_files
                             for parent in Path(name).parents}
                            if approved_files is not None else None)
    no_symlink(source)
    source_fd = os.open(source, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        source_uid = os.fstat(source_fd).st_uid
        for scope in scopes:
            if approved_directories is not None and scope not in approved_directories:
                continue
            cursor = os.dup(source_fd)
            try:
                for part in Path(scope).parts:
                    next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                                      dir_fd=cursor)
                    os.close(cursor)
                    cursor = next_fd
                for location, dirs, files, directory_fd in os.fwalk(
                        ".", topdown=True, follow_symlinks=False, dir_fd=cursor):
                    directory_info = os.fstat(directory_fd)
                    if (directory_info.st_uid != source_uid
                            or directory_info.st_mode & 0o005 != 0o005):
                        raise ValueError("Private Obsidian directory cannot be shared")
                    rel_dir = Path(location).relative_to(".")
                    dirs[:] = sorted(d for d in dirs
                                     if not d.startswith(".") and not d.startswith("__")
                                     and (approved_directories is None
                                          or str(Path(scope) / rel_dir / d) in approved_directories))
                    for d in dirs:
                        st = os.stat(d, dir_fd=directory_fd, follow_symlinks=False)
                        if not _stat.S_ISDIR(st.st_mode):
                            raise ValueError("Shared Obsidian catalogue contains unsafe directory")
                    for name in sorted(files):
                        rel = Path(scope) / rel_dir / name
                        if (scope == "tools" and str(rel) not in selected):
                            continue
                        if name.startswith(".") or name in {"auth.json", "credentials.json", "secrets.env"}:
                            continue
                        if Path(name).suffix.lower() not in allowed and str(rel) != "tools/bin/run-quiet":
                            continue  # executable tools get a separately reviewed install
                        if approved_files is not None and str(rel) not in approved_files:
                            continue
                        # Nonblocking open avoids root waiting indefinitely on
                        # an attacker-swapped FIFO. Validate the *opened* file,
                        # not an earlier pathname stat (including its privacy).
                        try:
                            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                                         dir_fd=directory_fd)
                        except OSError as error:
                            raise ValueError("Shared source must be a bounded regular file") from error
                        try:
                            checked = os.fstat(fd)
                            if (not _stat.S_ISREG(checked.st_mode)
                                    or checked.st_uid != source_uid
                                    or not checked.st_mode & 0o004
                                    or checked.st_size > 1024 * 1024):
                                raise ValueError(f"Shared source must be a public bounded regular file: {rel}")
                            with os.fdopen(fd, "rb", closefd=False) as handle:
                                content = handle.read(1024 * 1024 + 1)
                            after = os.fstat(fd)
                            if (checked.st_ino, checked.st_mtime_ns, checked.st_size) != (
                                    after.st_ino, after.st_mtime_ns, after.st_size):
                                raise ValueError("Obsidian source changed during snapshot")
                            if (checked.st_mode, checked.st_uid, checked.st_ctime_ns) != (
                                    after.st_mode, after.st_uid, after.st_ctime_ns):
                                raise ValueError("Obsidian source privacy changed during snapshot")
                        finally:
                            os.close(fd)
                        count += 1
                        total += len(content)
                        if len(content) > 1024 * 1024 or count > 500 or total > 8 * 1024 * 1024:
                            raise ValueError("Shared Obsidian resource limit exceeded")
                        if (approved_files is not None
                                and hashlib.sha256(content).hexdigest() != approved_files[str(rel)]):
                            raise ValueError(f"Shared resource differs from approved digest: {rel}")
                        target = destination / rel
                        target.parent.mkdir(parents=True, exist_ok=True)
                        target.write_bytes(content)
                        os.chmod(target, 0o444)
                        digests[str(rel)] = hashlib.sha256(content).hexdigest()
            finally:
                os.close(cursor)
    finally:
        os.close(source_fd)
    required = ("AgentSystem/agent-memory/skills/INDEX.md",
                "AgentSystem/agent-memory/boot/AGENT_STARTUP_PROTOCOL.md",
                "tools/agent-tool-policy.json", "tools/AGENT_TOOL_HANDOFF.md")
    if any(name not in digests for name in required):
        raise ValueError("Canonical shared Obsidian index is missing")
    return {"files": count, "bytes": total, "hashes": digests}


def stage_standalone_tools(policy_file: Path, destination: Path, *, approved_tools=None) -> dict:
    """Stage only inspected native ELF tools, never user-owned script wrappers.

    The host's /usr and /bin are already mounted read-only. Other tools can
    be admitted only as immutable, checksum-recorded native binaries. Python,
    Node/npm and package-manager wrappers require separate dependency-aware
    review; this deliberately does not falsely mark the whole inventory green.
    """
    import stat as _stat
    with policy_file.open("rb") as stream:
        policy = json.load(stream)
    required = policy["tools"]["required"]
    if (len(required) != 38 or len(set(required)) != 38 or
            any(not isinstance(name, str) or not name.replace("-", "").isalnum()
                for name in required)):
        raise ValueError("Unexpected Obsidian tool policy shape")
    approved_tools = approved_tools or {}
    destination.mkdir(parents=True, exist_ok=True)
    report = {"required": len(required), "provided_by_system": [],
              "bundled_elf": {}, "bundled_scripts": {}, "not_bundled": []}
    def system_tool(path):
        try:
            resolved = path.resolve(strict=True)
            return (resolved.is_file() and os.access(resolved, os.X_OK)
                    and resolved.is_relative_to(Path('/usr')) and resolved.stat().st_uid == 0)
        except OSError:
            return False
    for name in required:
        system_paths = [Path(root) / name for root in ("/usr/bin", "/bin", "/usr/local/bin")]
        if any(system_tool(path) for path in system_paths):
            report["provided_by_system"].append(name)
            continue
        found = False
        admission = approved_tools.get(name, {})
        source = Path(admission.get("source", "/not-approved"))
        if (not source.is_absolute()
                or not isinstance(admission.get("provenance"), str)
                or not admission.get("provenance")
                or not isinstance(admission.get("sha256"), str)
                or len(admission["sha256"]) != 64):
            report["not_bundled"].append(name)
            continue
        for root in (source.parent,):
            try:
                no_symlink(root)
                if not root.resolve().is_relative_to(Path("/home/yeli")):
                    continue
                dirfd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            except OSError:
                continue
            try:
                try:
                    fd = os.open(source.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=dirfd)
                except OSError:
                    continue
                try:
                    st = os.fstat(fd)
                    if (not _stat.S_ISREG(st.st_mode) or st.st_uid != pwd.getpwnam("yeli").pw_uid
                            or not st.st_mode & 0o111
                            or st.st_mode & 0o6002 or st.st_size < 4
                            or st.st_size > 128 * 1024 * 1024):
                        continue
                    with os.fdopen(fd, "rb", closefd=False) as handle:
                        data = handle.read(128 * 1024 * 1024 + 1)
                    if len(data) != st.st_size or data[:4] != b"\x7fELF":
                        continue
                    after = os.fstat(fd)
                    if ((st.st_dev, st.st_ino, st.st_size, st.st_mode, st.st_mtime_ns, st.st_ctime_ns)
                            != (after.st_dev, after.st_ino, after.st_size, after.st_mode,
                                after.st_mtime_ns, after.st_ctime_ns)
                            or hashlib.sha256(data).hexdigest() != admission["sha256"]):
                        raise ValueError(f"Tool differs from approved descriptor/digest: {name}")
                    target = destination / name
                    target.write_bytes(data)
                    os.chmod(target, 0o555)
                    report["bundled_elf"][name] = hashlib.sha256(data).hexdigest()
                    found = True
                    break
                finally:
                    os.close(fd)
            finally:
                os.close(dirfd)
        if not found:
            report["not_bundled"].append(name)
    # A single reviewed first-party Bash utility comes from the *snapshotted*
    # canonical tool policy tree. No other arbitrary shebang scripts qualify.
    runner = policy_file.parent / "bin/run-quiet"
    if runner.is_file() and not runner.is_symlink() and "run-quiet" in approved_tools:
        data = runner.read_bytes()
        if (0 < len(data) <= 8192 and data.startswith(b"#!/usr/bin/env bash\n")
                and "run-quiet" in required
                and hashlib.sha256(data).hexdigest() == approved_tools["run-quiet"].get("sha256")):
            target = destination / "run-quiet"
            target.write_bytes(data)
            os.chmod(target, 0o555)
            report["bundled_scripts"]["run-quiet"] = hashlib.sha256(data).hexdigest()
            if "run-quiet" in report["not_bundled"]:
                report["not_bundled"].remove("run-quiet")
    return report


def workspace_admissions(workspaces):
    """Explicit reviewed roots only; discovery/catalog rows cannot grant scope."""
    rows = workspaces.get('workspaces') if isinstance(workspaces, dict) else None
    if not isinstance(rows, dict) or set(rows) != set(WORKSPACES):
        raise ValueError('Workspace admission must name exactly the reviewed development workspaces')
    admitted = []
    seen = set()
    for name in sorted(rows):
        spec = rows[name]
        if not isinstance(spec, dict) or not isinstance(spec.get('path'), str):
            raise ValueError('Malformed workspace admission')
        path = Path(spec['path']).resolve(strict=True)
        writable = spec.get('writable', True)
        if (not path.is_dir() or path != Path(WORKSPACES[name]).resolve(strict=True)
                or path in seen or not isinstance(writable, bool)
                or spec.get('allow_agent_dispatch') is not True or spec.get('allow_execute', True) is not True):
            raise ValueError('Workspace admission differs from reviewed scope')
        seen.add(path)
        admitted.append({'path': str(path), 'writable': writable})
    return admitted


def snapshot(runtime, python_root, version, *, approvals=None, workspaces=None):
    if approvals is None:
        raise ValueError("Snapshot requires an explicit reviewed resource manifest")
    allowed_workspaces = workspace_admissions(workspaces)
    destination = INSTALL / 'versions' / version
    destination.mkdir(parents=True, mode=0o755)
    copy_tree(python_root, destination / 'python')
    (destination / 'venv').mkdir()
    copy_tree(REPO / '.venv/lib', destination / 'venv/lib')
    (destination / 'venv/bin').mkdir()
    (destination / 'venv/bin/python').symlink_to('../../python/bin/python3.13')
    atomic_text(destination / 'venv/pyvenv.cfg',
                f'home = {destination}/python/bin\nimplementation = CPython\nversion_info = 3.13.12.final.0\ninclude-system-site-packages = false\n')
    copy_tree(REPO / 'src', destination / 'src', ignore=shutil.ignore_patterns('__pycache__', '*.pyc'))
    packages = destination / 'venv/lib/python3.13/site-packages'
    for pth in packages.glob('*agentporter*.pth'):
        pth.unlink()
    atomic_text(packages / 'agentporter_development.pth', str(destination / 'src') + '\n', mode=0o644)
    shared = destination / "shared/obsidian"
    receipt = stage_shared_obsidian(OBSIDIAN, shared, approved_files=approvals.get("shared_files"))
    atomic_text(destination / "shared/manifest.json",
                json.dumps({"source": "canonical Obsidian snapshot",
                            "manifest": receipt}, sort_keys=True) + "\n", mode=0o644)
    toolkit_root = destination / "shared/toolkit"
    tools = stage_standalone_tools(shared / "tools/agent-tool-policy.json",
                                  toolkit_root / "bin", approved_tools=approvals.get("tools", {}))
    atomic_text(toolkit_root / "manifest.json",
                json.dumps(tools, sort_keys=True) + "\n", mode=0o644)
    rewritten = json.loads(json.dumps(runtime))
    rewritten['allowed_workspace_roots'] = allowed_workspaces
    rewritten["shared_obsidian"] = str(shared)
    rewritten["shared_toolkit"] = str(toolkit_root)
    for name, spec in rewritten['workers'].items():
        original = Path(spec['executable'])
        if original.is_file():
            executable = original.resolve()
            # Copy the same native platform binary selected by Phil's npm loader.
            if name == 'phil':
                executable = Path('/home/yeli/.nvm/versions/node/v24.15.0/lib/node_modules/@github/copilot/node_modules/@github/copilot-linux-x64/copilot')
                native = destination / 'cli/phil/copilot'
                native.parent.mkdir(parents=True, exist_ok=True)
                with executable.open('rb') as stream:
                    if stream.read(4) != b'\x7fELF':
                        raise ValueError('Phil native platform binary is missing or not ELF')
                shutil.copy2(executable, native)
                spec['executable'] = str(native)
                spec.pop('runtime_mounts', None)
            else:
                native = destination / 'cli' / name / executable.name
                native.parent.mkdir(parents=True, exist_ok=True)
                with executable.open('rb') as stream:
                    if stream.read(4) != b'\x7fELF':
                        raise ValueError(f'{name} needs an additional reviewed package mount; source executable is not native ELF')
                shutil.copy2(executable, native)
                spec['executable'] = str(native)
                spec.pop('runtime_mounts', None)
            if name in {'jax', 'liz', 'prof'}:
                helper = executable.with_name('codex-code-mode-host')
                if not helper.is_file() or helper.is_symlink() or not os.access(helper, os.X_OK):
                    raise ValueError(f'{name} matching bundled Codex code-mode helper is missing')
                with helper.open('rb') as stream:
                    if stream.read(4) != b'\x7fELF':
                        raise ValueError(f'{name} bundled Codex code-mode helper is not native ELF')
                installed_helper = native.with_name('codex-code-mode-host')
                shutil.copy2(helper, installed_helper)
                spec['code_mode_host'] = str(installed_helper)
        else:
            spec['executable'] = str(destination / 'missing' / name)
            spec.pop('runtime_mounts', None)
        spec['credentials'] = {target: str(DATA / 'credentials' / name / target)
                               for target in spec['credentials']}
        if spec.get('codex_config'):
            spec['codex_config'] = str(DATA / 'credentials' / name / '.codex/config.toml')
    immutable_tree(destination)
    return destination, rewritten


def secret_name(name):
    return (name == '.env' or name.startswith('.env.') or name.endswith(('.env', '.pem', '.key'))
            or name in {'auth.json', 'credentials.json', 'secrets.env'})


def grant_workspaces(workspaces, account, backup):
    for key, spec in workspaces['workspaces'].items():
        workspace = Path(spec['path']).resolve(strict=True)
        # Save complete ACL evidence before changing this named user's entries.
        saved = run(['getfacl', '-R', '-p', '--', workspace]).stdout
        atomic_text(backup / f'acl-{key}.txt', saved)
        for parent in reversed(workspace.parents):
            if parent != Path('/'):
                run(['setfacl', '-m', f'u:{account.pw_uid}:--x', '--', parent])
        writable = bool(spec.get('writable'))
        for current, directories, files in os.walk(workspace, followlinks=False):
            path = Path(current)
            access = 'rwx' if writable else 'r-x'
            run(['setfacl', '-m', f'u:{account.pw_uid}:{access},d:u:{account.pw_uid}:{access}', '--', path])
            for name in list(directories):
                child = path / name
                if child.is_symlink():
                    directories.remove(name)
                elif name == '.git':
                    run(['setfacl', '-R', '-P', '-m', f'u:{account.pw_uid}:r-X', '--', child])
                    for metadata_root, metadata_dirs, _ in os.walk(child, followlinks=False):
                        metadata_dirs[:] = [item for item in metadata_dirs
                                            if not (Path(metadata_root) / item).is_symlink()]
                        run(['setfacl', '-m', f'd:u:{account.pw_uid}:r-X', '--', metadata_root])
                    directories.remove(name)
                elif name in MASK_DIRS or name.startswith('.codex-') or secret_name(name):
                    run(['setfacl', '-m', f'u:{account.pw_uid}:---', '--', child])
                    directories.remove(name)
            groups = {}
            for name in files:
                child = path / name
                if child.is_symlink():
                    continue
                access = 'r--' if name == '.git' else '---' if secret_name(name) else 'rwX' if writable else 'r-X'
                groups.setdefault(access, []).append(child)
            for access, paths in groups.items():
                for offset in range(0, len(paths), 128):
                    run(['setfacl', '-m', f'u:{account.pw_uid}:{access}', '--', *paths[offset:offset + 128]])


def unit_text():
    return f'''[Unit]
Description=AgentPorter Development (separate account, port 8876)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User={ACCOUNT}
Group={ACCOUNT}
WorkingDirectory={DATA}/home
Environment=HOME={DATA}/home
Environment=AGENTPORTER_CONFIG_DIR={DATA}/config
Environment=AGENTPORTER_STATE_DIR={DATA}/state
Environment=AGENTPORTER_CACHE_DIR={DATA}/cache
Environment=PYTHONPATH={INSTALL}/current/src
Environment=PYTHONDONTWRITEBYTECODE=1
Environment=PATH=/usr/bin:/bin
ExecStart={INSTALL}/current/venv/bin/python -I -m agentporter.cli serve --config-dir {DATA}/config --host 127.0.0.1 --port 8876
Restart=on-failure
RestartSec=3
UMask=0077
NoNewPrivileges=true
RestrictSUIDSGID=true

[Install]
WantedBy=multi-user.target
'''


def copy_worker_credentials(runtime, rewritten, account):
    missing = []
    for name, original in runtime['workers'].items():
        for target, source in original['credentials'].items():
            destination = Path(rewritten['workers'][name]['credentials'][target])
            if destination.exists():
                no_symlink(destination)
                if not destination.is_file() or destination.stat().st_uid != account.pw_uid:
                    raise ValueError(f'Existing dev credential must be private and dev-owned: {destination}')
                os.chmod(destination, 0o600)
                continue  # Keep any refreshed development authentication.
            if not Path(source).is_file():
                missing.append(f'{name}: missing dedicated {target}')
                continue
            private_dir(destination.parent, account.pw_uid, account.pw_gid)
            # Credential contents never reach stdout, manifests, or command argv.
            atomic_text(destination, Path(source).read_text(), uid=account.pw_uid, gid=account.pw_gid)
    return missing


def report_inventory():
    """Ask the live dedicated gateway to run its own OS confinement probes."""
    path = DATA / 'config/secrets.env'
    no_symlink(path)
    keys = [line.partition('=')[2].strip() for line in path.read_text().splitlines()
            if line.startswith('AGENTPORTER_API_KEY=')]
    if len(keys) != 1 or not keys[0]:
        raise ValueError('Installed DEVELOPMENT API key missing; cannot verify live delegation')
    request = urllib.request.Request(
        'http://127.0.0.1:8876/api/v1/workspaces/m3-poc/agents/list',
        headers={'X-AgentPorter-Key': keys[0]})
    # Probes launch only inside the live gateway's verified Bubblewrap runtime;
    # the operator process neither imports project code nor runs a worker.
    with urllib.request.urlopen(request, timeout=180) as response:
        rows = json.load(response)
    if not isinstance(rows, list) or {row.get('agent') for row in rows} != set(AGENTS):
        raise ValueError('Live gateway inventory did not report exactly the seven expected identities')
    ready = 0
    for row in rows:
        available = bool(row.get('available') and row.get('delegatable'))
        ready += int(available)
        state = 'OS confinement verified; provider task smoke still required' if available else (
            'BLOCKED: ' + str(row.get('confinement_status', 'unavailable')) + '; ' +
            str(row.get('availability_reason', 'No verified launch reason supplied')))
        print(f'  {row["agent"]}: {state}')
    print(f'Delegation confinement verified for {ready}/7 identities; HTTP health alone does not establish delegation availability.')
    return rows


def apply(plan):
    config, runtime, workspaces, python_root, owner = plan
    if os.geteuid() != 0:
        raise PermissionError('--apply requires sudo with the distro /usr/bin/python3 -I interpreter')
    try:
        account = pwd.getpwnam(ACCOUNT)
    except KeyError:
        run(['useradd', '--system', '--user-group', '--home-dir', DATA / 'home',
             '--no-create-home', '--shell', '/usr/sbin/nologin', ACCOUNT])
        account = pwd.getpwnam(ACCOUNT)
    private_dir(DATA, 0, account.pw_gid)
    os.chmod(DATA, 0o710)
    for directory in ('home', 'state', 'cache', 'config', 'credentials'):
        private_dir(DATA / directory, account.pw_uid, account.pw_gid)
    version = datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%S.%fZ')
    backup = DATA / 'provisioning' / version
    backup.mkdir(parents=True, mode=0o700)
    os.chmod(backup.parent, 0o700)
    if SYSTEM_UNIT.exists():
        shutil.copy2(SYSTEM_UNIT, backup / 'previous-system-unit')
    for source in (DATA / 'config').iterdir():
        if source.is_file() and not source.is_symlink():
            shutil.copy2(source, backup / ('previous-' + source.name))
    INSTALL.mkdir(parents=True, exist_ok=True, mode=0o755)
    installed, rewritten = snapshot(runtime, python_root, version, workspaces=workspaces)
    missing = copy_worker_credentials(runtime, rewritten, account)
    config['server'] = {**config['server'], 'host': '127.0.0.1', 'port': 8876, 'name': 'AgentPorter Development'}
    for name, value in [('config.yaml', config), ('development-runtime.yaml', rewritten), ('workspaces.yaml', workspaces)]:
        atomic_text(DATA / 'config' / name, yaml.safe_dump(value, sort_keys=False), uid=account.pw_uid, gid=account.pw_gid)
    if (STAGE / 'agents.yaml').stat().st_size:
        atomic_text(DATA / 'config/agents.yaml', (STAGE / 'agents.yaml').read_text(), uid=account.pw_uid, gid=account.pw_gid)
    if not (DATA / 'config/secrets.env').exists():
        # Preserve only the existing STAGING DEVELOPMENT key, never a production key.
        no_symlink(STAGE / 'secrets.env')
        keys = [line.partition('=')[2].strip() for line in (STAGE / 'secrets.env').read_text().splitlines()
                if line.startswith('AGENTPORTER_API_KEY=')]
        if len(keys) != 1 or len(keys[0]) < 24 or any(char.isspace() for char in keys[0]):
            raise ValueError('Staging development API key missing/invalid; no production key will be used')
        atomic_text(DATA / 'config/secrets.env', 'AGENTPORTER_API_KEY=' + keys[0] + '\n', uid=account.pw_uid, gid=account.pw_gid)
    grant_workspaces(workspaces, account, backup)
    temporary = INSTALL / 'current.provision-new'
    if temporary.exists() or temporary.is_symlink():
        raise ValueError('Interrupted prior current.provision-new exists; inspect before retry')
    temporary.symlink_to(installed)
    os.replace(temporary, INSTALL / 'current')
    # Stop exactly the old DEVELOPMENT user unit, never production.
    user_env = {'PATH': '/usr/bin:/bin', 'HOME': owner.pw_dir,
                'XDG_RUNTIME_DIR': f'/run/user/{owner.pw_uid}',
                'DBUS_SESSION_BUS_ADDRESS': f'unix:path=/run/user/{owner.pw_uid}/bus'}
    old = run(['runuser', '-u', owner.pw_name, '--', '/usr/bin/env', '-i',
               *(f'{key}={value}' for key, value in user_env.items()), '/usr/bin/systemctl', '--user',
               'stop', UNIT_NAME], check=False)
    if old.returncode and 'not exist' not in old.stderr and 'not loaded' not in old.stderr:
        raise RuntimeError('Could not stop the existing DEVELOPMENT user unit; inspect user systemd before starting port 8876')
    if SYSTEM_UNIT.exists():
        run(['systemctl', 'stop', UNIT_NAME])  # Existing dedicated development system unit only.
    with socket.socket() as port_check:
        port_check.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            port_check.bind(('127.0.0.1', 8876))
        except OSError as error:
            raise RuntimeError('Development port 8876 is still occupied; no unrelated process will be stopped') from error
    atomic_text(SYSTEM_UNIT, unit_text(), mode=0o644)
    manifest = {'version': version, 'snapshot': str(installed), 'account_uid': account.pw_uid,
                'unit': str(SYSTEM_UNIT), 'workspaces': list(workspaces['workspaces']),
                'missing_credentials': missing, 'source_python': str(python_root),
                'source_module_sha256': hashlib.sha256((REPO / 'src/agentporter/agents/development.py').read_bytes()).hexdigest(),
                'production_service_changed': False}
    atomic_text(backup / 'manifest.json', json.dumps(manifest, indent=2) + '\n')
    run(['systemctl', 'daemon-reload'])
    run(['systemctl', 'enable', UNIT_NAME])
    run(['systemctl', 'restart', UNIT_NAME])  # Development only, including reruns.
    run(['systemctl', 'is-active', '--quiet', UNIT_NAME])
    for attempt in range(20):
        try:
            with urllib.request.urlopen('http://127.0.0.1:8876/health', timeout=2) as response:
                if response.status == 200:
                    break
        except OSError:
            if attempt == 19:
                raise RuntimeError('Development service started but health failed; inspect its development unit logs')
            time.sleep(1)
    print(f'Development system unit started; health HTTP 200. Evidence/ACL backups: {backup}')
    inventory = report_inventory()
    manifest['verified_inventory'] = inventory
    atomic_text(backup / 'manifest.json', json.dumps(manifest, indent=2) + '\n')
    for item in missing:
        print('Unavailable until dedicated credential provisioned: ' + item)
    print('Verify: sudo systemctl status agentporter-development.service --no-pager')
    print('Health: curl --fail http://127.0.0.1:8876/health')
    print('API key remains private in /var/lib/agentporter-dev/config/secrets.env; it was not printed.')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--apply', action='store_true', help='Apply this development-only plan as root; default validates/prints only')
    args = parser.parse_args()
    try:
        plan = validate_inputs()
        _, runtime, workspaces, python_root, owner = plan
        print('Validated Asgard development-only plan (production gateway will not be restarted):')
        print(f'  Dedicated account: {ACCOUNT}, distinct from production UID {owner.pw_uid}')
        print(f'  Immutable installed source/dependency/CLI snapshot: {INSTALL}/versions/<timestamp>')
        print(f'  Offline Python interpreter source: {python_root}')
        print(f'  Private config/state/cache/home and separate credential copies: {DATA}')
        print(f'  Workspace ACLs: {", ".join(workspaces["workspaces"])}; Git read-only, secret paths excluded')
        print(f'  Stop only old yeli user {UNIT_NAME}; start separate system {UNIT_NAME} on 127.0.0.1:8876')
        for name, spec in runtime['workers'].items():
            missing = [target for target, source in spec['credentials'].items() if not Path(source).is_file()]
            print(f'  {name}: ' + ('dedicated credential missing: ' + ', '.join(missing) if missing else 'credential files exist; runtime/provider smoke checks still required'))
        if args.apply:
            apply(plan)
        else:
            print('Dry run only. To apply: sudo /usr/bin/python3 -I ' + str(REPO / 'scripts/provision-development-runtime.py') + ' --apply')
    except (OSError, ValueError, KeyError, RuntimeError, subprocess.SubprocessError) as error:
        raise SystemExit('Provisioning stopped: ' + str(error))


if __name__ == '__main__':
    main()
