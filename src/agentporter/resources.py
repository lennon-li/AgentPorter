"""Aggregate per-job cgroup v2 envelopes; no privileged setup or fallback.

The operator must delegate cpu/memory/pids and place the gateway in a supervisor
subgroup. Workers cannot see cgroupfs. Limits are applied before worker exec.
"""
import os
from pathlib import Path
import re
import sys
import threading
import time
import uuid


class JobCapacityError(RuntimeError):
    pass


class ResourceCleanupError(RuntimeError):
    pass


class JobResources:
    def __init__(self, settings):
        if set(settings) != {'memory_bytes', 'pids', 'cpu_quota_us', 'cpu_period_us'}:
            raise ValueError('Explicit CPU, memory and process budgets required')
        bounds = {'memory_bytes': (512 * 1024**2, 16 * 1024**3), 'pids': (16, 512),
                  'cpu_quota_us': (10000, 400000), 'cpu_period_us': (100000, 100000)}
        for name, (low, high) in bounds.items():
            if type(settings[name]) is not int or not low <= settings[name] <= high:
                raise ValueError('Invalid job resource budget: ' + name)
        current = Path('/proc/self/cgroup').read_text().strip()
        if not current.startswith('0::/') or '\n' in current:
            raise PermissionError('Unified cgroup v2 is required')
        relative = Path(current[3:])
        if relative.name != 'supervisor' or relative.parent.name != 'agentporter-development.service':
            raise PermissionError('Owner-installed DelegateSubgroup=supervisor is required')
        self.root = Path('/sys/fs/cgroup') / str(relative.parent).lstrip('/')
        if self.root.is_symlink() or self.root.stat().st_uid != os.getuid():
            raise PermissionError('Cgroup root is not delegated to the gateway UID')
        controllers = (self.root / 'cgroup.controllers').read_text().split()
        if not {'cpu', 'memory', 'pids'}.issubset(controllers):
            raise PermissionError('CPU/memory/pids controllers must be delegated')
        (self.root / 'cgroup.subtree_control').write_text('+cpu +memory +pids')
        self.settings = dict(settings)

    def create(self):
        path = self.root / ('apj_' + uuid.uuid4().hex)
        path.mkdir(mode=0o700)
        try:
            limits = {'memory.max': str(self.settings['memory_bytes']), 'memory.swap.max': '0',
                      'memory.oom.group': '1', 'pids.max': str(self.settings['pids']),
                      'cpu.max': f"{self.settings['cpu_quota_us']} {self.settings['cpu_period_us']}"}
            for name, value in limits.items():
                (path / name).write_text(value)
                if (path / name).read_text().strip() != value:
                    raise PermissionError('Kernel did not apply resource limit: ' + name)
            return ResourceLease(path)
        except BaseException:
            path.rmdir()
            raise

    def recover(self):
        """Only on exclusive gateway startup: terminate prior job envelopes."""
        supervisor = (self.root / 'supervisor/cgroup.procs').read_text().split()
        if supervisor != [str(os.getpid())] or (self.root / 'cgroup.procs').read_text().strip():
            raise PermissionError('Exclusive gateway supervisor membership required for recovery')
        for path in self.root.iterdir():
            if path.is_dir() and path.name != 'supervisor' and not re.fullmatch(r'apj_[0-9a-f]{32}', path.name):
                raise PermissionError('Unknown child cgroup; recovery requires review')
            if re.fullmatch(r'apj_[0-9a-f]{32}', path.name):
                if path.is_symlink() or path.stat().st_uid != os.getuid():
                    raise PermissionError('Untrusted recovery cgroup')
                ResourceLease(path).close()


class ResourceLease:
    def __init__(self, path):
        self.path = Path(path)
        self._lock = threading.Lock()
        self._closed = False

    def command(self, command):
        return [sys.executable, '-I', '-m', 'agentporter.resource_runner',
                '--cgroup', str(self.path), '--', *command]

    def terminate(self):
        """Kill the entire owned envelope now, including setsid descendants.

        This requests termination, not successful cleanup. Only close() proves
        populated=0 and removes the envelope. Serialize with monitor cleanup.
        """
        with self._lock:
            if not self._closed:
                try:
                    (self.path / 'cgroup.kill').write_text('1')
                except Exception as error:
                    raise ResourceCleanupError('Job tree termination remains unverified') from error

    def close(self):
        with self._lock:
            try:
                self._close_locked()
            except ResourceCleanupError:
                raise
            except Exception as error:
                raise ResourceCleanupError('Job envelope cleanup remains unverified') from error

    def _close_locked(self):
        if self._closed:
            return
        if not self.path.exists():
            raise ResourceCleanupError('Owned job cgroup disappeared before cleanup proof')
        (self.path / 'cgroup.kill').write_text('1')
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline:
            events = dict(line.split() for line in (self.path / 'cgroup.events').read_text().splitlines())
            if events.get('populated') == '0':
                self.path.rmdir()
                self._closed = True
                return
            time.sleep(0.02)
        raise ResourceCleanupError('Job cgroup did not drain; admission must remain held')
