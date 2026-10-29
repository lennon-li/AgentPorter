"""Enter an operator-delegated supervisor subgroup on systemd before v254.

Run only as the dedicated non-root worker service, from its immutable release.
This creates no delegation or permissions; systemd must provide those first.
"""
from __future__ import annotations

import argparse
import os
from pathlib import Path
import stat
import sys


SERVICE_UNITS = frozenset({'agentporter-bcc-worker.service', 'agentporter-development.service',
                           'agentporter-bcc-gateway.service'})


def _membership(path: Path) -> Path:
    text = path.read_text().strip()
    if not text.startswith('0::/') or '\n' in text:
        raise PermissionError('Unified cgroup v2 membership is required')
    relative = Path(text[3:])
    if any(part in {'.', '..'} for part in text[3:].split('/')):
        raise PermissionError('Invalid cgroup membership')
    return relative


def _directory(path: Path) -> None:
    info = path.lstat()
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid()
            or info.st_mode & 0o022):
        raise PermissionError('Cgroup directory must be privately delegated to this UID')


def enter_supervisor(*, cgroup_mount: Path = Path('/sys/fs/cgroup'),
                     membership_file: Path = Path('/proc/self/cgroup')) -> Path:
    """Move only this process; reject busy, foreign or unexpected cgroups."""
    if os.getuid() == 0 or os.geteuid() != os.getuid():
        raise PermissionError('Supervisor bootstrap requires an unprivileged service identity')
    relative = _membership(membership_file)
    already_entered = relative.name == 'supervisor'
    service = relative.parent if already_entered else relative
    if service.name not in SERVICE_UNITS:
        raise PermissionError('Unexpected worker service cgroup')
    root = cgroup_mount / str(service).lstrip('/')
    if root.resolve(strict=True) != root:
        raise PermissionError('Cgroup ancestors must not be symlinks')
    _directory(root)
    if not {'cpu', 'memory', 'pids'} <= set((root / 'cgroup.controllers').read_text().split()):
        raise PermissionError('CPU/memory/pids delegation is required')
    pid = str(os.getpid())
    parent_members = (root / 'cgroup.procs').read_text().split()
    if parent_members != ([] if already_entered else [pid]):
        raise PermissionError('Exclusive worker service membership is required')
    for child in root.iterdir():
        if child.is_dir() and child.name != 'supervisor':
            # Stale job envelopes are recovered by JobResources after startup.
            import re
            if not re.fullmatch(r'apj_[0-9a-f]{32}', child.name) or child.is_symlink():
                raise PermissionError('Unknown child cgroup; operator review required')
    supervisor = root / 'supervisor'
    supervisor.mkdir(mode=0o700, exist_ok=True)
    _directory(supervisor)
    members = (supervisor / 'cgroup.procs').read_text().split()
    if members != ([pid] if already_entered else []):
        raise PermissionError('Supervisor subgroup is not exclusive')
    if not already_entered:
        fd = os.open(supervisor / 'cgroup.procs', os.O_WRONLY | os.O_NOFOLLOW)
        try:
            if os.write(fd, pid.encode()) != len(pid):
                raise PermissionError('Incomplete supervisor membership write')
        finally:
            os.close(fd)
    if (_membership(membership_file).name != 'supervisor'
            or _membership(membership_file).parent != service
            or (root / 'cgroup.procs').read_text().split()
            or (supervisor / 'cgroup.procs').read_text().split() != [pid]):
        raise PermissionError('Kernel supervisor membership remains unverified')
    return root


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config-dir', required=True)
    parser.add_argument('--probe', action='store_true', help='Check delegated startup only; do not serve')
    args = parser.parse_args()
    root = enter_supervisor()
    if args.probe:
        print('Supervisor membership verified: ' + str(root))
        return
    port = '8765' if root.name == 'agentporter-bcc-gateway.service' else '8876'
    os.execv(sys.executable, [sys.executable, '-I', '-m', 'agentporter.cli', 'serve',
                             '--config-dir', args.config_dir, '--host', '127.0.0.1', '--port', port])


if __name__ == '__main__':
    main()
