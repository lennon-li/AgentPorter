#!/usr/bin/env python3
"""Owner-run, sealed production-only permission migration. No Git publication.

The owner pauses submissions before running the packet. All model credentials,
provider routes, specialized configuration and retired development units remain
untouched. A failed activation restores both release pointers, original controls
and ACLs. New runtime state/job history is retained, never rolled back or erased.
"""
from __future__ import annotations

import hashlib
import fcntl
import importlib.util
import json
import os
from pathlib import Path
import pwd
import shutil
import stat
import subprocess
import sys
import time
import urllib.request
import uuid


def require(value, message):
    if not value: raise RuntimeError(message)


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def atomic(path, data, uid=0, gid=0, mode=0o600):
    path = Path(path)
    temporary = path.with_name('.install-' + uuid.uuid4().hex)
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    try:
        os.fchown(fd, uid, gid); os.fchmod(fd, mode)
        with os.fdopen(fd, 'wb', closefd=False) as stream:
            stream.write(data); stream.flush(); os.fsync(fd)
        os.replace(temporary, path)
    finally:
        os.close(fd); temporary.unlink(missing_ok=True)


def symlink(path, target, uid=0, gid=0):
    temporary = path.with_name('.link-' + uuid.uuid4().hex)
    try:
        temporary.symlink_to(target); os.lchown(temporary, uid, gid); os.replace(temporary, path)
    finally: temporary.unlink(missing_ok=True)


SYSTEM_PATH = '/usr/sbin:/usr/bin:/sbin:/bin'


def command(argv, *, env=None, report_stderr=False):
    try:
        return subprocess.run(list(map(str, argv)), check=True, capture_output=True, text=True,
                              timeout=180, env=env if env is not None else
                              {'PATH': SYSTEM_PATH, 'LANG': 'C.UTF-8'})
    except subprocess.CalledProcessError as error:
        # Opt in only for commands whose stderr cannot contain credentials.
        if report_stderr:
            raise RuntimeError(f'{Path(argv[0]).name} exited {error.returncode}: '
                               + (error.stderr.strip() or 'no error details reported')) from error
        raise


def owns_listener(pid, port):
    """Check the kernel socket inode before sending a credential to localhost."""
    try:
        sockets = set()
        for descriptor in Path(f'/proc/{pid}/fd').iterdir():
            try: target = os.readlink(descriptor)
            except FileNotFoundError: continue
            if target.startswith('socket:['): sockets.add(target[8:-1])
        for name in ('tcp', 'tcp6'):
            for line in Path(f'/proc/{pid}/net/{name}').read_text().splitlines()[1:]:
                fields = line.split()
                if fields[3] == '0A' and int(fields[1].split(':')[1], 16) == port and fields[9] in sockets:
                    return True
    except (OSError, ValueError, IndexError): pass
    return False


class Installation:
    def __init__(self, packet):
        require(os.geteuid() == 0, 'Run this owner-approved installer with sudo')
        self.lock = os.open('/run/agentporter-workspace-policy.lock',
                            os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        fcntl.flock(self.lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        self.packet = Path(packet).resolve(strict=True)
        self.manifest = json.loads((self.packet / 'manifest.json').read_text())
        actual = {p.relative_to(self.packet).as_posix() for p in self.packet.rglob('*') if not p.is_dir()}
        require(actual == set(self.manifest['files']) | {'manifest.json'}, 'Unexpected packet contents')
        for rel, sha in self.manifest['files'].items():
            path = self.packet / rel
            require(not Path(rel).is_absolute() and all(p not in {'.', '..'} for p in Path(rel).parts)
                    and not path.is_symlink() and path.resolve().is_relative_to(self.packet)
                    and digest(path) == sha, 'Packet file hash or path mismatch')
        self.home = Path(self.manifest['gateway_home'])
        self.user = pwd.getpwuid(self.home.stat().st_uid)
        require(self.user.pw_uid != 0 and Path(self.user.pw_dir) == self.home,
                'Gateway identity changed')
        self.worker = pwd.getpwnam('agentporter-worker')
        require(self.worker.pw_uid not in {0, self.user.pw_uid}, 'Worker identity is not separate')
        self.env = {'PATH': SYSTEM_PATH, 'LANG': 'C.UTF-8',
                    'XDG_RUNTIME_DIR': f'/run/user/{self.user.pw_uid}',
                    'DBUS_SESSION_BUS_ADDRESS': f'unix:path=/run/user/{self.user.pw_uid}/bus'}
        self.deploy = self.home / '.local/share/agentporter'
        self.worker_root = Path('/opt/agentporter-worker')
        self.old_gateway = self.deploy.joinpath('current').resolve(strict=True)
        self.old_worker = self.worker_root.joinpath('current').resolve(strict=True)
        require(str(self.old_gateway) == self.manifest['gateway_base'], 'Gateway release changed')
        require(str(self.old_worker) == self.manifest['worker_base'], 'Worker release changed')
        self.stage = Path('/usr/local/libexec/agentporter/workspace-policy') / self.manifest['artifact_id']
        require(not self.stage.exists(), 'This sealed installation already has an operator journal')
        self.stage.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
        self.stage.mkdir(mode=0o700)
        for rel, expected in self.manifest['files'].items():
            descriptor = os.open(self.packet / rel, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            try:
                require(stat.S_ISREG(os.fstat(descriptor).st_mode), 'Invalid packet file type')
                data = os.read(descriptor, 8 * 1024**2 + 1)
                require(hashlib.sha256(data).hexdigest() == expected, 'Packet changed during sealing')
            finally: os.close(descriptor)
            target = self.stage / rel; target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            atomic(target, data)
        atomic(self.stage / 'manifest.json', json.dumps(self.manifest).encode())
        for path in [self.stage, *self.stage.rglob('*')]:
            require(not path.is_symlink(), 'Symlink in sealed operator packet')
            os.chown(path, 0, 0); path.chmod(0o555 if path.is_dir() else 0o444)
        self.recovery = self.stage / 'recovery'; self.recovery.mkdir(mode=0o700)
        sys.path.insert(0, str(self.stage / 'source'))
        spec = importlib.util.spec_from_file_location('sealed_production_config_migration',
            self.stage / 'scripts/migrate-production-workspace-policy.py')
        self.migration = importlib.util.module_from_spec(spec); spec.loader.exec_module(self.migration)
        self.plan_sha = None
        self.config_applied = False
        self.acl_plan = None
        self.acl_applied_paths = []
        self.saved_units = {}
        self.helpers_enabled = False
        self.links = {}
        self.fixture = None
        self.fixture_identity = None
        self.new_gateway = self.deploy / 'releases' / self.manifest['artifact_id']
        self.new_worker = self.worker_root / 'versions' / self.manifest['worker_version']

    def human(self, argv):
        return command(['/usr/sbin/runuser', '-u', self.user.pw_name, '--', *argv], env=self.env)

    def userctl(self, *args):
        return command(['/usr/sbin/runuser', '-u', self.user.pw_name, '--',
                        '/usr/bin/systemctl', '--user', *args], env=self.env, report_stderr=True)
    def systemctl(self, *args): return command(['/usr/bin/systemctl', *args], report_stderr=True)

    def api(self, path):
        pid = int(self.userctl('show', 'agentporter.service', '--property=MainPID', '--value').stdout.strip())
        require(pid > 0 and owns_listener(pid, 8765), 'Production gateway does not own its API listener')
        values = {}
        for line in (self.home / '.config/agentporter/secrets.env').read_text().splitlines():
            if '=' in line:
                name, value = line.split('=', 1); values[name] = value.strip()
        key = values.get('AGENTPORTER_API_KEY') or values.get('API_KEY')
        require(bool(key), 'Existing API credential is unavailable')
        request = urllib.request.Request('http://127.0.0.1:8765' + path,
            headers={'Authorization': 'Bearer ' + key})
        with urllib.request.urlopen(request, timeout=15) as response: return json.load(response)

    def health(self, port):
        deadline = time.monotonic() + 45
        while time.monotonic() < deadline:
            try:
                control = self.userctl if port == 8765 else self.systemctl
                unit = 'agentporter.service' if port == 8765 else 'agentporter-worker.service'
                pid = int(control('show', unit, '--property=MainPID', '--value').stdout.strip())
                if pid <= 0 or not owns_listener(pid, port):
                    time.sleep(.25); continue
                with urllib.request.urlopen(f'http://127.0.0.1:{port}/health', timeout=2) as response:
                    if json.load(response).get('status') == 'healthy': return
            except Exception: pass
            time.sleep(.25)
        raise RuntimeError('Production service did not become healthy')

    def idle(self):
        self.migration.idle(self.home / '.local/state/agentporter/jobs.db', self.user.pw_uid)
        self.migration.idle(Path('/var/lib/agentporter-worker/state/jobs.db'), self.worker.pw_uid)

    def clone_release(self, base, target, uid, gid, worker=False):
        require(not target.exists(), 'Candidate release path already exists')
        target.mkdir(mode=0o700)
        shutil.copytree(base / 'venv', target / 'venv', symlinks=True)
        for path in [target / 'venv', *(target / 'venv').rglob('*')]:
            if not path.is_symlink() and path.is_dir(): path.chmod(0o700)
        original_venv = (base / 'venv').resolve(strict=True)
        for source in (base / 'venv').rglob('*'):
            if not source.is_symlink(): continue
            resolved = source.resolve(strict=True)
            # Preserve internal links within the new venv. Pin external
            # dependencies to their existing immutable location: worker Python
            # lives at base/python, outside the directory copied above.
            destination = (target / 'venv' / resolved.relative_to(original_venv)
                           if resolved.is_relative_to(original_venv) else resolved)
            link = target / 'venv' / source.relative_to(base / 'venv')
            link.unlink(); link.symlink_to(destination)
        shutil.copytree(self.stage / 'source', target / 'src')
        sites = list((target / 'venv/lib').glob('python*/site-packages'))
        require(len(sites) == 1, 'Unexpected production virtualenv layout')
        package = sites[0] / 'agentporter'
        if package.is_symlink(): package.unlink()
        elif package.exists(): shutil.rmtree(package)
        shutil.copytree(self.stage / 'source/agentporter', package)
        for pth in sites[0].glob('agentporter*.pth'):
            pth.chmod(0o600); pth.write_text(str(target / 'src') + '\n')
        metadata = {'artifact_id': self.manifest['artifact_id'],
                    'artifact_source': 'sealed uncommitted source; no Git commit created',
                    'base_release': str(base), 'runtime_dependency': str(base),
                    'fingerprint': self.manifest['package_fingerprint'], 'package_path': str(package)}
        (target / 'RELEASE.json').write_text(json.dumps(metadata, indent=2) + '\n')
        if worker:
            (target / 'operator-checks').mkdir(mode=0o755)
            shutil.copyfile(self.stage / 'scripts/validate-production-workspace-writes.py',
                            target / 'operator-checks/validate-production-workspace-writes.py')
        for path in [target, *target.rglob('*')]:
            if path.is_symlink():
                os.lchown(path, uid, gid)
            else:
                mode = 0o555 if path.is_dir() or path.stat().st_mode & 0o111 else 0o444
                os.chown(path, uid, gid); path.chmod(mode)

    def validate_release_runtime(self, release, *, worker=False, policy_document=None):
        identity = self.worker if worker else self.user
        code = ("import json,sys; from pathlib import Path; "
                "import agentporter,agentporter.cli,agentporter.workspace_view_service,agentporter.workspace_views; "
                "from agentporter.deployinfo import source_fingerprint; "
                "release=Path(sys.argv[1]); "
                "assert Path(sys.prefix)==release/'venv', 'Wrong virtualenv prefix'; "
                "assert Path(agentporter.__file__).is_relative_to(release/'venv'), 'Wrong package origin'; "
                "assert source_fingerprint()==sys.argv[2], 'Wrong package fingerprint'; "
                "proof={'uid':__import__('os').getuid(),'prefix':sys.prefix,'fingerprint':source_fingerprint()}\n"
                "if sys.argv[3] != 'null':\n"
                " import tempfile\n"
                " from agentporter.workspace_policy import WorkspacePolicy\n"
                " from agentporter.workspaces.registry import WorkspaceRegistry\n"
                " from agentporter.client_policy import PublicClientPolicy\n"
                " policy=WorkspacePolicy(json.loads(sys.argv[3]))\n"
                " registry=WorkspaceRegistry(policy.workspaces,workspace_policy=policy)\n"
                " compiler=object.__new__(PublicClientPolicy)\n"
                " compiler.registry=registry; compiler.workspace_policy=policy\n"
                " compiler.allow_production_scinet=sys.argv[4]=='gateway'\n"
                " scopes=compiler.scopes\n"
                " with tempfile.TemporaryDirectory(prefix='a7-policy-preflight-') as raw:\n"
                "  root=Path(raw); cfg=root/'config'; state=root/'state'\n"
                "  cfg.mkdir(mode=0o700); state.mkdir(mode=0o700)\n"
                "  control=cfg/'public-client-policy.yaml'\n"
                "  control.write_text(json.dumps({'version':1,'workspaces':{name:{'path':registry.get(name).path,'operations':sorted(ops)} for name,ops in scopes.items()}}))\n"
                "  control.chmod(0o600)\n"
                "  checked=PublicClientPolicy(cfg,state,registry,required=True,allow_production_scinet=compiler.allow_production_scinet)\n"
                "  assert checked.scopes==scopes, 'Candidate public scope compilation mismatch'\n"
                " proof['planned_public_policy_verified']=True\n"
                "print(json.dumps(proof))")
        result = command(['/usr/sbin/runuser', '-u', identity.pw_name, '--',
            release / 'venv/bin/python', '-I', '-B', '-c', code,
            release, self.manifest['package_fingerprint'], json.dumps(policy_document),
            'worker' if worker else 'gateway'],
            env=self.env, report_stderr=True)
        proof = json.loads(result.stdout)
        require(proof['uid'] == identity.pw_uid, 'Candidate runtime identity mismatch')
        return proof

    def save_links(self):
        for root in (self.deploy, self.worker_root):
            for name in ('current', 'previous'):
                path = root / name
                self.links[str(path)] = os.readlink(path) if path.is_symlink() else None
        atomic(self.recovery / 'release-links.json', json.dumps(self.links).encode())

    def install_unit(self, name, user=False):
        directory = self.home / '.config/systemd/user' if user else Path('/etc/systemd/system')
        target = directory / name
        uid, gid = (self.user.pw_uid, self.user.pw_gid) if user else (0, 0)
        body = (self.stage / 'examples' / name).read_bytes()
        if target.exists() or target.is_symlink():
            info = target.lstat()
            require(stat.S_ISREG(info.st_mode) and info.st_uid == uid and info.st_nlink == 1
                    and stat.S_IMODE(info.st_mode) == 0o644 and target.read_bytes() == body,
                    'An unexpected view-helper unit already exists; review it before migration')
            return  # Preserve an identical, already installed helper and its enablement.
        self.saved_units[str(target)] = name
        atomic(target, body, uid, gid, 0o644)

    def stop(self):
        self.userctl('stop', 'agentporter.service')
        self.systemctl('stop', 'agentporter-worker.service')
        self.idle()

    def start(self):
        self.systemctl('start', 'agentporter-worker-workspace-views.service')
        self.userctl('start', 'agentporter-workspace-views.service')
        self.systemctl('start', 'agentporter-worker.service')
        self.userctl('start', 'agentporter.service')
        self.health(8876); self.health(8765)

    def validate_worker(self):
        from agentporter.workspace_policy import load_workspace_policy
        policy = load_workspace_policy()
        root = Path(policy.workspaces['m3-poc']['path'])
        name = '.a7-permission-check-' + uuid.uuid4().hex
        self.fixture = root / name
        self.fixture.mkdir(mode=0o700); os.chown(self.fixture, self.user.pw_uid, self.user.pw_gid)
        self.fixture_identity = (self.fixture.stat().st_dev, self.fixture.stat().st_ino)
        atomic(self.fixture / 'existing.txt', b'before', self.user.pw_uid, self.user.pw_gid, 0o600)
        from agentporter.workspace_access import plan, apply
        from types import SimpleNamespace
        fixture_policy = SimpleNamespace(workspaces={'fixture': {'path': str(self.fixture)}},
            protected_paths=(), capabilities=lambda _: {'writable': True})
        local_plan = plan(fixture_policy, self.worker.pw_uid, include_ancestors=False)
        apply(local_plan)
        result = command(['/usr/sbin/runuser', '-u', self.worker.pw_name, '--',
            str(self.new_worker / 'venv/bin/python'), '-I',
            str(self.new_worker / 'operator-checks/validate-production-workspace-writes.py'),
            '--workspace', 'm3-poc', '--fixture', name], report_stderr=True)
        proof = json.loads(result.stdout.strip().splitlines()[-1])
        require(proof['publication'] and proof['unapproved_delete_rejected'], 'Worker validation failed')
        self.human([str(self.new_gateway / 'venv/bin/python'), '-I', '-c',
            "from pathlib import Path; import sys; p=Path(sys.argv[1]); "
            "assert (p/'existing.txt').read_text()=='after'; assert (p/'new.txt').read_text()=='new'; "
            "(p/'new.txt').write_text('human-edit')", str(self.fixture)])
        proof['human_read_write_verified'] = True
        return proof

    def cleanup_fixture(self):
        if self.fixture is None: return
        info = self.fixture.lstat()
        require((info.st_dev, info.st_ino) == self.fixture_identity and not self.fixture.is_symlink(),
                'Validation fixture identity changed')
        require(set(p.name for p in self.fixture.iterdir()) <= {'existing.txt', 'new.txt'},
                'Unexpected validation fixture contents; retained for review')
        for path in self.fixture.iterdir():
            require(path.is_file() and not path.is_symlink() and path.stat().st_nlink == 1,
                    'Validation output changed type')
            path.unlink()
        self.fixture.rmdir(); self.fixture = None

    def prepare_native_verification(self):
        """Owner approves only exact, expiring edits to new disposable marker files."""
        from agentporter.workspace_policy import load_workspace_policy
        from agentporter.workspace_access import plan, apply
        from agentporter.agents.production_relay import normalize_dispatch
        from agentporter.agents.roster import PUBLIC_AGENT_IDS
        from agentporter.scoped_approvals import load_private_key, sign_grant
        from types import SimpleNamespace
        root = Path(load_workspace_policy().workspaces['m3-poc']['path'])
        folder = root / ('.a7-permission-verification-' + uuid.uuid4().hex)
        folder.mkdir(mode=0o700); os.chown(folder, self.user.pw_uid, self.user.pw_gid)
        key = load_private_key('/etc/agentporter/approval-issuer.key')
        requests = {}
        now = int(time.time())
        for agent in sorted(PUBLIC_AGENT_IDS):
            marker = folder / (agent + '.txt')
            atomic(marker, b'before', self.user.pw_uid, self.user.pw_gid, 0o600)
            task = (f'Write exactly A7_WORKSPACE_WRITE_OK to the existing file '
                    f'{folder.name}/{agent}.txt in this workspace. Change no other file. '
                    'Do not commit or push. Report whether the file edit succeeded.')
            args = normalize_dispatch({'workspace_id': 'm3-poc', 'agent': agent, 'task': task,
                                       'purpose': 'Production workspace permission verification', 'read_only': False})
            token = sign_grant(key, workspace_id='m3-poc', workspace_root=str(root),
                action='dispatch_agent', arguments=args, operations=['write'], agent=agent,
                issued_at=now, expires_at=now + 3600)
            requests[agent] = {**args, 'approval_token': token, 'request_id': uuid.uuid4().hex}
        fixture_policy = SimpleNamespace(workspaces={'fixture': {'path': str(folder)}}, protected_paths=(),
                                         capabilities=lambda _: {'writable': True})
        apply(plan(fixture_policy, self.worker.pw_uid, include_ancestors=False))
        target = self.home / '.local/state/agentporter/workspace-policy-verification.json'
        atomic(target, json.dumps({'fixture': str(folder), 'expires_at': now + 3600, 'requests': requests}).encode(),
               self.user.pw_uid, self.user.pw_gid)

    def execute(self):
        from agentporter.deployinfo import source_fingerprint
        from agentporter.workspace_access import plan, apply
        from agentporter.workspace_policy import load_workspace_policy, WorkspacePolicy
        print('Checking current releases and idle production services...', flush=True)
        require(self.systemctl('show', 'agentporter-worker.service', '--property=ActiveState', '--value').stdout.strip() == 'active',
                'The production worker is not active')
        require(self.systemctl('show', 'agentporter-development.service', '--property=ActiveState', '--value').stdout.strip() in {'inactive', 'failed'},
                'The retired development service is unexpectedly active; no change made')
        running = self.api('/api/v1/server/deploy-info')
        require(running['pid'] == int(self.userctl('show', 'agentporter.service', '--property=MainPID', '--value').stdout.strip()),
                'Gateway port owner does not match the production unit')
        require(running['loaded_fingerprint'] == self.manifest['gateway_fingerprint'],
                'Running gateway fingerprint changed')
        self.health(8876); self.idle(); self.save_links()
        # Validate the complete configuration and directory trust while services
        # are still running. apply() repeats this with the stopped-state gate.
        changes = self.migration.build(self.home, require_stopped=False)
        self.plan_sha = self.migration.fingerprint(changes)
        config_recovery = self.migration.recovery_path(self.plan_sha, self.manifest['artifact_id'])
        require(not config_recovery.exists() and not config_recovery.is_symlink(),
                'This configuration recovery attempt already exists')
        policy_document = self.migration.yaml.safe_load(changes[str(self.migration.POLICY)]['after'][0])
        policy = WorkspacePolicy(policy_document)
        require(len(policy.workspaces) == 11 and all(policy.capabilities(n)['writable'] for n in policy.workspaces),
                'Unified eleven-workspace policy did not compile')
        print('Planning scoped filesystem access while production remains running...', flush=True)
        acl_plan = plan(policy, self.worker.pw_uid,
                        progress=lambda counts: print('ACL plan: ' + json.dumps(counts), flush=True))
        atomic(self.recovery / 'workspace-access.json', json.dumps(acl_plan).encode())
        print(f"ACL plan complete: {acl_plan['scanned']} entries, {len(acl_plan['records'])} changes.", flush=True)
        if not Path('/usr/bin/fuse-overlayfs').exists():
            print('Installing the sealed distro copy-on-write helper...', flush=True)
            command(['/usr/bin/dpkg', '-i', self.stage / 'dependencies/fuse-overlayfs.deb'],
                    report_stderr=True)
        print('Preparing immutable production releases...', flush=True)
        self.clone_release(self.old_gateway, self.new_gateway, self.user.pw_uid, self.user.pw_gid)
        self.clone_release(self.old_worker, self.new_worker, 0, 0, worker=True)
        require(source_fingerprint(self.new_gateway / 'src/agentporter') == self.manifest['package_fingerprint'],
                'Candidate source fingerprint mismatch')
        print('Executing both candidate runtimes as their service accounts before shutdown...', flush=True)
        runtime_proof = {'gateway': self.validate_release_runtime(self.new_gateway, policy_document=policy_document),
                         'worker': self.validate_release_runtime(self.new_worker, worker=True, policy_document=policy_document)}
        self.install_unit('agentporter-workspace-views.service', user=True)
        self.install_unit('agentporter-worker-workspace-views.service')
        for directory, uid, gid in (
            (self.home / '.local/state/agentporter/workspace-views', self.user.pw_uid, self.user.pw_gid),
            (Path('/var/lib/agentporter-worker/state/workspace-views'), self.worker.pw_uid, self.worker.pw_gid)):
            directory.mkdir(mode=0o700, exist_ok=True); os.chown(directory, uid, gid); directory.chmod(0o700)
        self.systemctl('daemon-reload'); self.userctl('daemon-reload')
        stopped = False
        try:
            print('Stopping idle production services and applying shared policy...', flush=True)
            stopped = True; self.stop()
            self.systemctl('stop', 'agentporter-worker-workspace-views.service')
            self.userctl('stop', 'agentporter-workspace-views.service')
            self.migration.apply(self.home, self.plan_sha, attempt_id=self.manifest['artifact_id'])
            self.config_applied = True
            policy = load_workspace_policy()
            require(len(policy.workspaces) == 11 and all(policy.capabilities(n)['writable'] for n in policy.workspaces),
                    'Unified eleven-workspace policy did not compile')
            print('Applying the preflighted worker filesystem access...', flush=True)
            self.acl_plan = acl_plan
            apply(self.acl_plan, applied_paths=self.acl_applied_paths)
            symlink(self.worker_root / 'previous', self.links[str(self.worker_root / 'current')])
            symlink(self.worker_root / 'current', self.new_worker)
            symlink(self.deploy / 'previous', self.links[str(self.deploy / 'current')], self.user.pw_uid, self.user.pw_gid)
            symlink(self.deploy / 'current', self.new_gateway, self.user.pw_uid, self.user.pw_gid)
            print('Starting private view helpers and verifying real worker/human writes...', flush=True)
            self.systemctl('start', 'agentporter-worker-workspace-views.service')
            self.userctl('start', 'agentporter-workspace-views.service')
            # Wait for the independently managed private sockets before the check.
            deadline = time.monotonic() + 10
            socket_path = Path('/run/agentporter-workspace-views/socket')
            while not socket_path.exists() and time.monotonic() < deadline: time.sleep(.1)
            proof = self.validate_worker(); self.cleanup_fixture()
            print('Starting production and checking the live eleven-workspace matrix...', flush=True)
            self.start()
            info = self.api('/api/v1/server/deploy-info')
            require(info['loaded_fingerprint'] == self.manifest['package_fingerprint'] and not info['stale'],
                    'Running candidate fingerprint mismatch')
            rows = self.api('/api/v1/workspaces/')
            require(isinstance(rows, list) and len(rows) == 11, 'Live workspace inventory is not eleven rows')
            require(all(row['writable'] and all(row['permissions'][key] for key in
                ('execute', 'git', 'artifacts', 'agent_dispatch')) for row in rows),
                'Live workspace defaults differ')
            self.helpers_enabled = True
            self.systemctl('enable', 'agentporter-worker-workspace-views.service')
            self.userctl('enable', 'agentporter-workspace-views.service')
            self.prepare_native_verification()
            evidence = {'installed': True, 'artifact_id': self.manifest['artifact_id'],
                        'fingerprint': info['loaded_fingerprint'], 'workspaces': 11,
                        'all_writable': True, 'all_delegation_enabled': True, 'worker_validation': proof,
                        'runtime_preflight': runtime_proof,
                        'native_provider_delegation': 'not yet verified on this candidate'}
            atomic(self.home / '.local/state/agentporter/workspace-policy-install.json',
                   json.dumps(evidence, indent=2).encode(), self.user.pw_uid, self.user.pw_gid)
            print(json.dumps(evidence, sort_keys=True), flush=True)
        except BaseException:
            print('Activation failed; restoring previous production controls and releases...', flush=True)
            if stopped:
                self.userctl('stop', 'agentporter.service'); self.systemctl('stop', 'agentporter-worker.service')
                self.userctl('stop', 'agentporter-workspace-views.service')
                self.systemctl('stop', 'agentporter-worker-workspace-views.service')
                if self.fixture is not None: self.cleanup_fixture()
                if self.acl_plan is not None:
                    apply(self.acl_plan, rollback=True, applied_paths=self.acl_applied_paths)
                if self.config_applied:
                    self.migration.rollback(self.home, self.plan_sha, attempt_id=self.manifest['artifact_id'])
                for path, target in self.links.items():
                    uid, gid = (self.user.pw_uid, self.user.pw_gid) if str(path).startswith(str(self.deploy)) else (0, 0)
                    if target is None: Path(path).unlink(missing_ok=True)
                    else: symlink(Path(path), target, uid, gid)
                if self.helpers_enabled:
                    for path, name in self.saved_units.items():
                        control = self.userctl if str(path).startswith(str(self.home)) else self.systemctl
                        control('disable', name)
                for path, name in self.saved_units.items():
                    require(Path(path).read_bytes() == (self.stage / 'examples' / name).read_bytes(),
                            'Helper unit changed during activation; retained for review')
                    Path(path).unlink()
                self.systemctl('daemon-reload'); self.userctl('daemon-reload')
                if Path('/etc/systemd/system/agentporter-worker-workspace-views.service').exists():
                    self.systemctl('start', 'agentporter-worker-workspace-views.service')
                if (self.home / '.config/systemd/user/agentporter-workspace-views.service').exists():
                    self.userctl('start', 'agentporter-workspace-views.service')
                self.systemctl('start', 'agentporter-worker.service'); self.userctl('start', 'agentporter.service')
                self.health(8876); self.health(8765)
                restored = self.api('/api/v1/server/deploy-info')
                require(restored['loaded_fingerprint'] == self.manifest['gateway_fingerprint'] and not restored['stale'],
                        'Previous production fingerprint was not restored')
                print('Previous production releases restored and healthy.', flush=True)
            raise


if __name__ == '__main__':
    try: Installation(sys.argv[1]).execute()
    except Exception as error:
        print('Production permission installation stopped: ' + type(error).__name__ + ': ' + str(error), file=sys.stderr)
        raise SystemExit(1)
