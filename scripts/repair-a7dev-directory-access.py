#!/usr/bin/python3
"""Run as operator with this launcher's reviewed SHA256 pinned by the caller.

Root executes fixed stdlib bootstrap code. Root's sole filesystem mutation is
0710 -> 0750 on the existing root-owned private A7Dev data directory. Policy
validation runs as the service account using its immutable installed release.
"""
import os
import subprocess


BOOTSTRAP = r'''
import errno,grp,json,os,pwd,stat,subprocess,sys,time,urllib.request
from pathlib import Path

DATA = '/var/lib/agentporter-dev'
ACCOUNT = 'agentporter-dev'
UNIT = 'agentporter-development.service'
RELEASE = '/opt/agentporter-development/versions/20261020T223443.649130Z'
ENV = {'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LANG':'C.UTF-8'}
PROBE = ('from pathlib import Path; from agentporter.config import Config; '
         'from agentporter.server import create_asgi_app; '
         'p=Path("/var/lib/agentporter-dev/config/secrets.env"); '
         'assert p.is_file() and not p.is_symlink(), "Existing private gateway key file required"; '
         'create_asgi_app(Config(config_dir=Path("/var/lib/agentporter-dev/config"), '
         'state_dir=Path("/var/lib/agentporter-dev/state"), '
         'cache_dir=Path("/var/lib/agentporter-dev/cache")))')

def trusted_directory(path):
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        info = os.fstat(fd)
        if info.st_uid != 0 or info.st_mode & 0o022:
            raise PermissionError('Untrusted root directory')
        for component in Path(path).parts[1:]:
            child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = child
            info = os.fstat(fd)
            if info.st_uid != 0 or info.st_mode & 0o022:
                raise PermissionError('Untrusted root-owned ancestor')
        return fd
    except BaseException:
        os.close(fd)
        raise

def private_account():
    account = pwd.getpwnam(ACCOUNT)
    group = grp.getgrnam(ACCOUNT)
    if (account.pw_uid in (0, pwd.getpwnam('operator').pw_uid) or group.gr_gid == 0
            or account.pw_gid != group.gr_gid
            or set(group.gr_mem) - {ACCOUNT}
            or {row.pw_name for row in pwd.getpwall() if row.pw_gid == group.gr_gid} != {ACCOUNT}
            or set(os.getgrouplist(ACCOUNT, account.pw_gid)) != {account.pw_gid}):
        raise PermissionError('A7Dev service group is not exclusive and private')
    return account

def validate_data(fd, account):
    info = os.fstat(fd)
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != 0
            or info.st_gid != account.pw_gid or stat.S_IMODE(info.st_mode) not in (0o710, 0o750)):
        raise PermissionError('Unexpected A7Dev data owner/group/mode')
    try:
        os.getxattr(fd, 'system.posix_acl_access')
    except OSError as error:
        if error.errno not in (errno.ENODATA, errno.ENOTSUP, errno.EOPNOTSUPP):
            raise
    else:
        raise PermissionError('Unexpected A7Dev data access ACL')
    return info

def installed_interpreter():
    fd = trusted_directory('/opt/agentporter-development')
    try:
        if os.readlink('current', dir_fd=fd) != RELEASE:
            raise PermissionError('Current release is not the admitted A7Dev v8 release')
    finally:
        os.close(fd)
    interpreter = Path(RELEASE) / 'venv/bin/python'
    resolved = interpreter.resolve(strict=True)
    if not resolved.is_relative_to(Path(RELEASE)):
        raise PermissionError('Installed interpreter escapes the admitted release')
    for directory in (interpreter.parent, resolved.parent, Path(RELEASE) / 'src'):
        fd = trusted_directory(directory)
        os.close(fd)
    info = resolved.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0
            or info.st_mode & 0o022 or not info.st_mode & 0o111):
        raise PermissionError('Installed interpreter is not immutable root-owned code')
    return str(interpreter)

def existing_private_key(data_fd, account):
    config = os.open('config', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=data_fd)
    try:
        info = os.fstat(config)
        if info.st_uid != account.pw_uid or info.st_gid != account.pw_gid or stat.S_IMODE(info.st_mode) != 0o700:
            raise PermissionError('Unexpected private A7Dev config directory')
        key = os.open('secrets.env', os.O_PATH | os.O_NOFOLLOW, dir_fd=config)
        try:
            info = os.fstat(key)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != account.pw_uid
                    or info.st_gid != account.pw_gid or stat.S_IMODE(info.st_mode) != 0o600):
                raise PermissionError('Existing private A7Dev gateway key metadata required')
        finally:
            os.close(key)
    finally:
        os.close(config)

def probe_startup(interpreter):
    subprocess.run(['/usr/sbin/runuser','-u',ACCOUNT,'--','/usr/bin/env','-i',
                    'PATH=/usr/bin:/bin','LANG=C.UTF-8','HOME=/var/lib/agentporter-dev/home',
                    'PYTHONDONTWRITEBYTECODE=1',
                    interpreter,'-I','-B','-c',PROBE], check=True, env=ENV,
                   stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                   stderr=subprocess.DEVNULL, cwd='/var/lib/agentporter-dev/home', timeout=30)

def healthy():
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *args, **kwargs):
            return None
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    deadline = time.monotonic() + 30
    consecutive = 0
    previous = None
    while time.monotonic() < deadline:
        try:
            with opener.open('http://127.0.0.1:8876/health', timeout=2) as response:
                body = response.read(1025)
                valid = response.status == 200 and len(body) <= 1024 and json.loads(body) == {'status':'healthy'}
            result = subprocess.run(['/usr/bin/systemctl','show',UNIT,
                                     '--property=ActiveState,MainPID,NRestarts'],
                                    check=True, env=ENV, stdin=subprocess.DEVNULL,
                                    stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                    text=True, timeout=5)
            state = dict(line.split('=', 1) for line in result.stdout.splitlines())
            snapshot = (int(state['MainPID']), int(state['NRestarts']))
            active = state['ActiveState'] == 'active' and snapshot[0] > 0 and snapshot[1] >= 0
            consecutive = (consecutive + 1 if snapshot == previous else 1) if valid and active else 0
            previous = snapshot if valid and active else None
            if consecutive >= 3:
                return
        except (OSError, ValueError, KeyError, subprocess.SubprocessError):
            consecutive = 0
            previous = None
        time.sleep(1)
    raise RuntimeError('A7Dev did not remain active and healthy within the bounded check')

def main():
    if os.geteuid() != 0 or not sys.flags.isolated:
        raise PermissionError('Use the pinned launcher with isolated root Python')
    os.umask(0o077)
    account = private_account()
    interpreter = installed_interpreter()
    fd = trusted_directory(DATA)
    changed = False
    stopped = False
    try:
        before = validate_data(fd, account)
        existing_private_key(fd, account)
        subprocess.run(['/usr/bin/systemctl','stop',UNIT], check=True, env=ENV,
                       stdin=subprocess.DEVNULL, timeout=30)
        stopped = True
        if stat.S_IMODE(before.st_mode) == 0o710:
            os.fchmod(fd, 0o750)
            changed = True
        after = validate_data(fd, account)
        if (after.st_dev, after.st_ino, after.st_uid, after.st_gid, stat.S_IMODE(after.st_mode)) != (before.st_dev, before.st_ino, 0, account.pw_gid, 0o750):
            raise PermissionError('Data directory changed during repair')
        probe_startup(interpreter)
        subprocess.run(['/usr/bin/systemctl','restart',UNIT], check=True, env=ENV,
                       stdin=subprocess.DEVNULL, timeout=30)
        healthy()
    except BaseException:
        if stopped:
            try:
                result = subprocess.run(['/usr/bin/systemctl','stop',UNIT], check=False, env=ENV,
                                        stdin=subprocess.DEVNULL, timeout=30)
                if result.returncode != 0:
                    print('Development service stop could not be confirmed.', flush=True)
            except (OSError, subprocess.SubprocessError):
                print('Development service stop could not be confirmed.', flush=True)
            print('A7Dev validation failed; development stop requested. No automatic rollback.', flush=True)
        if changed:
            print('A7Dev directory read permission retained at 0750.', flush=True)
        raise
    finally:
        os.close(fd)
    print('A7Dev directory mode 0750 verified; full installed startup passed as service UID; development service active and healthy with stable PID/restart count.', flush=True)

if __name__ == '__main__':
    main()
'''


def main():
    if os.geteuid() == 0:
        raise SystemExit('Run this pinned launcher as operator; it invokes the fixed sudo bootstrap')
    subprocess.run(['/usr/bin/sudo', '/usr/bin/python3', '-I', '-B', '-c', BOOTSTRAP], check=True)


if __name__ == '__main__':
    main()
