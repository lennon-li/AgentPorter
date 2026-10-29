"""Fixed-purpose, same-UID copy-on-write view service.

This service alone may use the distribution's fusermount helper. It has no
provider credentials, command API, publication API or caller-selected mounts.
The gateway/job services retain NoNewPrivileges. Model processes cannot reach
this service's private socket, lower directories, upper directories or workdirs.
"""
from __future__ import annotations

import argparse
import array
import json
import logging
import os
from pathlib import Path
import pwd
import select
import shutil
import socket
import stat
import struct
import subprocess
import tempfile
import threading
import time

from agentporter.workspace_policy import load_workspace_policy

MAX_MESSAGE = 4096
MAX_CHANGED_FILES = 10000
MAX_CHANGED_BYTES = 64 * 1024 * 1024
FUSE_PROGRAM = Path('/usr/bin/fuse-overlayfs')
UNMOUNT_PROGRAM = '/usr/bin/fusermount3'


def endpoint():
    if pwd.getpwuid(os.getuid()).pw_name == 'agentporter-worker':
        return Path('/run/agentporter-workspace-views/socket')
    return Path(f'/run/user/{os.getuid()}/agentporter-workspace-views/socket')


def private_directory(path):
    path = Path(path)
    if not path.is_absolute() or path.resolve() != path:
        raise PermissionError('View state must have a canonical path')
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    for node in (path, *path.parents):
        info = node.lstat()
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid not in {0, os.getuid()}
                or (info.st_mode & 0o022 and not (info.st_uid == 0 and info.st_mode & stat.S_ISVTX))):
            raise PermissionError('Untrusted view state ancestor')
    info = path.lstat()
    if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
        raise PermissionError('View state must be private to the service identity')
    return path


def _within_budget(upper):
    count = total = 0
    for location, dirs, files in os.walk(upper, followlinks=False):
        for name in dirs + files:
            info = (Path(location) / name).lstat()
            count += 1
            total += info.st_size if stat.S_ISREG(info.st_mode) else 0
            if count > MAX_CHANGED_FILES or total > MAX_CHANGED_BYTES:
                return False
    return True


class WorkspaceViewServer:
    def __init__(self, policy, state_dir, *, mount_program=FUSE_PROGRAM):
        self.policy = policy
        self.state_dir = private_directory(state_dir)
        self.mount_program = Path(mount_program)
        self.slots = threading.BoundedSemaphore(6)

    def _check_program(self):
        path = self.mount_program
        info = path.lstat()
        if (not stat.S_ISREG(info.st_mode) or info.st_uid not in {0, os.getuid()}
                or info.st_mode & 0o6022 or not info.st_mode & 0o111):
            raise PermissionError('Untrusted copy-on-write executable')
        for row in self.policy.workspaces.values():
            root = Path(row['path'])
            if path == root or path.is_relative_to(root) or self.state_dir.is_relative_to(root):
                raise PermissionError('View controls overlap an authorized workspace')

    def handle(self, channel):
        """One connection owns one view lease; disconnect always discards it."""
        daemon = None
        owned = None
        source_fd = None
        acquired = False
        try:
            peer_pid, peer_uid, _ = struct.unpack('3i', channel.getsockopt(
                socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize('3i')))
            if peer_uid != os.getuid():
                raise PermissionError('Different view client identity')
            channel.settimeout(5)
            packet = channel.recv(MAX_MESSAGE + 1)
            if len(packet) > MAX_MESSAGE:
                raise ValueError('Oversized view request')
            request = json.loads(packet)
            if request == {'operation': 'ping'}:
                self._check_program()
                channel.send(b'{"status":"healthy"}')
                return
            if (not isinstance(request, dict) or set(request) != {'operation', 'workspace_root'}
                    or request['operation'] != 'create'):
                raise PermissionError('Unsupported view request')
            root = request['workspace_root']
            matches = [name for name, row in self.policy.workspaces.items()
                       if row['path'] == root]
            if not matches or not any(self.policy.capabilities(name)['writable'] for name in matches):
                raise PermissionError('Workspace is not eligible for a private writable view')
            for name in matches:
                self.policy.check_path(name, root, 'write')
            self._check_program()
            if not self.slots.acquire(blocking=False):
                raise PermissionError('View capacity exhausted')
            acquired = True
            logging.getLogger(__name__).info(json.dumps({'event': 'workspace_view_create',
                'workspace_id': matches[0], 'client_pid': peer_pid, 'service_uid': peer_uid}))
            source_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            if Path(root).resolve(strict=True) != Path(root):
                raise PermissionError('Workspace root changed')
            owned = Path(tempfile.mkdtemp(prefix='view-', dir=self.state_dir))
            for name in ('upper', 'work', 'merged'):
                (owned / name).mkdir(mode=0o700)
            started_ns = time.time_ns()
            options = (f'lowerdir=/proc/self/fd/{source_fd},upperdir={owned}/upper,'
                       f'workdir={owned}/work,squash_to_uid={os.getuid()},'
                       f'squash_to_gid={os.getgid()},noacl')
            # Foreground child: no daemonization, ambient environment or model code.
            daemon = subprocess.Popen([str(self.mount_program), '-f', '-o', options,
                                       str(owned / 'merged')],
                                      pass_fds=(source_fd,), stdin=subprocess.DEVNULL,
                                      stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                      env={'PATH': '/usr/bin:/bin', 'LANG': 'C'},
                                      start_new_session=True)
            deadline = time.monotonic() + 5
            while not os.path.ismount(owned / 'merged'):
                if daemon.poll() is not None or time.monotonic() > deadline:
                    raise PermissionError('Copy-on-write mount failed')
                time.sleep(.01)
            descriptor = os.open(owned / 'merged', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                payload = json.dumps({'status': 'created', 'lease_dir': str(owned),
                                      'started_ns': started_ns}).encode()
                channel.sendmsg([payload], [(socket.SOL_SOCKET, socket.SCM_RIGHTS,
                                             array.array('i', [descriptor]))])
            finally:
                os.close(descriptor)
            channel.settimeout(None)
            while True:
                ready, _, _ = select.select([channel], [], [], .1)
                if ready:
                    if channel.recv(32) not in (b'', b'close'):
                        raise PermissionError('Unexpected view lease operation')
                    break
                if daemon.poll() is not None or not _within_budget(owned / 'upper'):
                    raise PermissionError('Copy-on-write view exceeded its job budget or stopped')
        except (OSError, ValueError, PermissionError) as error:
            logging.getLogger(__name__).warning(json.dumps({'event': 'workspace_view_denied',
                'error_type': type(error).__name__}))
            try:
                channel.send(b'{"status":"denied"}')
            except OSError:
                pass
        finally:
            cleaned = True
            if owned is not None:
                # Only this private, uniquely created mount can be detached. A
                # caller must reap its producer before requesting normal cleanup.
                # Disconnect on caller death discards output even if a job lingers.
                if os.path.ismount(owned / 'merged'):
                    result = subprocess.run([UNMOUNT_PROGRAM, '-u', '-z', str(owned / 'merged')],
                                            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                            stderr=subprocess.DEVNULL, timeout=5, check=False)
                    cleaned = result.returncode == 0
                if daemon is not None:
                    if daemon.poll() is None:
                        daemon.terminate()
                    try:
                        daemon.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        daemon.kill()
                        daemon.wait(timeout=5)
                if cleaned:
                    shutil.rmtree(owned)
            if source_fd is not None:
                os.close(source_fd)
            if acquired:
                self.slots.release()
                logging.getLogger(__name__).info(json.dumps({'event': 'workspace_view_cleanup',
                    'verified': cleaned}))
            try:
                channel.send(b'closed' if cleaned else b'cleanup_failed')
            except OSError:
                pass
            channel.close()

    def serve(self, socket_path):
        path = Path(socket_path)
        private_directory(path.parent)
        self._check_program()
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        try:
            listener.bind(str(path))
            path.chmod(0o600)
            identity = path.lstat()
            listener.listen(6)
            while True:
                channel, _ = listener.accept()
                threading.Thread(target=self.handle, args=(channel,), daemon=True).start()
        finally:
            listener.close()
            if path.exists() and 'identity' in locals() and path.lstat().st_ino == identity.st_ino:
                path.unlink()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--state-dir', type=Path, required=True)
    options = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format='%(message)s')
    # The production CLI never accepts executable paths, workspace paths,
    # client identities or an alternative policy from a caller.
    program = FUSE_PROGRAM.lstat()
    if program.st_uid != 0 or program.st_mode & 0o6022:
        raise PermissionError('The system copy-on-write executable must be root-controlled')
    WorkspaceViewServer(load_workspace_policy(), options.state_dir).serve(endpoint())


if __name__ == '__main__':
    main()
