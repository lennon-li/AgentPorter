"""Owner-approved fetch: quarantine, validate, and advance one tracking ref."""
import hashlib
import json
import os
from pathlib import Path
import stat
import tempfile
import uuid

from agentporter.admission import execution_slot, synchronous_slot
from agentporter.git_admission import bind, resolve
from agentporter.git_approval_state import _INSPECT, _same_identity, locked_git_request
from agentporter.git_approvals import GitApprovalRequest
from agentporter.git_commits import _MetadataMount, _sync
from agentporter.git_pushes import _MAX_PACK, _write_private
from agentporter.git_smart_http import validate_pack
from agentporter.resources import ResourceCleanupError
from agentporter.workspaces.leases import workspace_key

_TRACK = r'''
import os, subprocess, sys
ref = sys.argv[1]; width = int(sys.argv[2])
env = {'PATH':'/usr/bin:/bin','LANG':'C','LC_ALL':'C','HOME':'/nonexistent',
 'GIT_CONFIG_NOSYSTEM':'1','GIT_CONFIG_GLOBAL':'/dev/null','GIT_NO_REPLACE_OBJECTS':'1',
 'GIT_NO_LAZY_FETCH':'1','GIT_TERMINAL_PROMPT':'0','GIT_OPTIONAL_LOCKS':'0'}
result = subprocess.run(['/usr/bin/git','--git-dir=/workspace/.git','-c','core.hooksPath=/dev/null',
 'for-each-ref','--format=%(refname) %(objectname)',ref],env=env,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,
 stderr=subprocess.DEVNULL,timeout=5,check=False)
if result.returncode or len(result.stdout)>4096:
 raise RuntimeError('Cannot inspect local tracking ref')
lines=result.stdout.decode('ascii').splitlines()
if not lines:
 print('0' * width)
elif len(lines)==1 and lines[0].startswith(ref+' ') and len(lines[0].split(' '))==2 and len(lines[0].split(' ')[1])==width and all(c in '0123456789abcdef' for c in lines[0].split(' ')[1]):
 print(lines[0].split(' ')[1])
else:
 raise RuntimeError('Cannot inspect local tracking ref')
'''

_INDEX = r'''
import contextlib, io, json, os, pathlib, subprocess, sys
request = json.loads(sys.argv[1]); expected = sys.argv[3]
namespace = {}
with contextlib.redirect_stdout(io.StringIO()): exec(sys.argv[2], namespace)
if any(namespace[n] != request[k] for n,k in [('head','expected_head'),('tree','expected_tree'),('branch','branch')]):
 raise RuntimeError('Local repository changed before approved fetch')
env = dict(namespace['environment'], GIT_DIR='/workspace/.git', GIT_WORK_TREE='/workspace',
 GIT_OBJECT_DIRECTORY='/out/objects', GIT_ALTERNATE_OBJECT_DIRECTORIES='/workspace/.git/objects',
 GIT_GRAFT_FILE='/dev/null')
base = ['/usr/bin/git','-c','safe.directory=/workspace','-c','core.hooksPath=/dev/null',
 '-c','core.fsmonitor=false','-c','protocol.allow=never']
os.mkdir('/out/objects',0o700); os.mkdir('/out/objects/pack',0o700)
with open('/in/pack','rb') as source:
 result = subprocess.run(base+['index-pack','--stdin','--strict'],stdin=source,stdout=subprocess.PIPE,
  stderr=subprocess.DEVNULL,env=env,timeout=40,check=False)
output=result.stdout.decode('ascii').splitlines()
if result.returncode or len(output)!=1 or not output[0].startswith('pack\t'):
 raise RuntimeError('Quarantine index-pack failed')
pack_hash=output[0][5:]
if any(c not in '0123456789abcdef' for c in pack_hash): raise RuntimeError('Invalid quarantine pack identity')
run_status=subprocess.run(base+['cat-file','-t',expected],env=env,stdin=subprocess.DEVNULL,
 stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=5,check=False)
if run_status.returncode or run_status.stdout.strip()!=b'commit': raise RuntimeError('Fetched branch does not identify a commit')
check=subprocess.run(base+['fsck','--strict','--no-reflogs','--connectivity-only',expected],env=env,
 stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=20,check=False)
if check.returncode or len(check.stdout)>4096: raise RuntimeError('Fetched commit graph failed strict validation')
print(pack_hash)
'''

_UPDATE = r'''
import contextlib, io, json, os, subprocess, sys
request=json.loads(sys.argv[1]); namespace={}
with contextlib.redirect_stdout(io.StringIO()): exec(sys.argv[2],namespace)
if any(namespace[n] != request[k] for n,k in [('head','expected_head'),('tree','expected_tree'),('branch','branch')]):
 raise RuntimeError('Local repository changed before tracking update')
p=request['parameters']; env=dict(namespace['environment'],GIT_DIR='/workspace/.git',GIT_WORK_TREE='/workspace')
base=['/usr/bin/git','-c','safe.directory=/workspace','-c','core.hooksPath=/dev/null','-c','core.fsmonitor=false','-c','protocol.allow=never']
r=subprocess.run(base+['cat-file','-t',p['remote_oid']],env=env,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=5)
if r.returncode or r.stdout.strip()!=b'commit': raise RuntimeError('Validated fetched commit is unavailable')
r=subprocess.run(base+['update-ref','-m','AgentPorter owner-approved fetch',p['tracking_ref'],p['remote_oid'],p['old_oid']],
 env=env,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=5)
if r.returncode: raise RuntimeError('Tracking ref changed before compare-and-swap')
print(p['remote_oid'])
'''


def _validate_tracking_ref(remote_id, branch):
    if not isinstance(remote_id, str) or not remote_id or any(not (c.isascii() and (c.isalnum() or c in '_-')) for c in remote_id):
        raise PermissionError('Invalid protected remote identity')
    if not isinstance(branch, str) or not branch.startswith('refs/heads/'):
        raise PermissionError('Fetch requires one exact protected branch')
    tracking = 'refs/remotes/' + remote_id + '/' + branch.removeprefix('refs/heads/')
    if len(tracking.encode()) > 1024 or any(p in {'', '.', '..'} or p.startswith('.') or p.endswith(('.', '.lock')) for p in tracking.split('/')):
        raise PermissionError('Invalid local tracking ref')
    return tracking


def _tracking_tip(sandbox, root, tracking, algorithm):
    result = sandbox._run_command(workspace_path=str(root),
        argv=['/usr/bin/python3','-I','-S','-c',_TRACK,tracking,'64' if algorithm=='sha256' else '40'], writable=False,
        git_metadata_writable=False,network_access=False,timeout_seconds=10,max_output_bytes=256)
    value=result['stdout'].strip()
    if result['exit_code'] or len(value) != (64 if algorithm=='sha256' else 40) or any(c not in '0123456789abcdef' for c in value):
        raise PermissionError('Cannot inspect exact local tracking ref')
    return value


def _write_fetch_guard(path, document):
    """Publish a complete durable guard atomically, never a partial JSON file."""
    path = Path(path)
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    parent = os.open(path.parent, flags)
    temp = '.git-fetch-pending-' + uuid.uuid4().hex
    descriptor = None
    try:
        parent_info = os.fstat(parent)
        if (not stat.S_ISDIR(parent_info.st_mode) or parent_info.st_uid != os.getuid()
                or parent_info.st_mode & 0o077):
            raise PermissionError('Fetch guard directory is not private')
        descriptor = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                             0o600, dir_fd=parent)
        raw = json.dumps(document, sort_keys=True, separators=(',', ':')).encode('utf-8')
        view = memoryview(raw)
        while view:
            view = view[os.write(descriptor, view):]
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = None
        os.link(temp, path.name, src_dir_fd=parent, dst_dir_fd=parent, follow_symlinks=False)
        os.fsync(parent)
    finally:
        if descriptor is not None:
            os.close(descriptor)
        try:
            os.unlink(temp, dir_fd=parent)
            os.fsync(parent)
        except FileNotFoundError:
            pass
        finally:
            os.close(parent)


def _promote_quarantine(metadata_fd, quarantine, pack_hash):
    """Install validated Git-produced pack/index without overwriting owner objects."""
    source = Path(quarantine) / 'objects' / 'pack'
    objects_fd = os.open('objects', os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC, dir_fd=metadata_fd)
    try:
        try:
            os.mkdir('pack',0o700,dir_fd=objects_fd)
        except FileExistsError:
            pass
        target_fd = os.open('pack', os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC, dir_fd=objects_fd)
        source_fd = os.open(source,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
        try:
          os.fsync(target_fd)
          for suffix in ('.idx','.pack'):
            name='pack-'+pack_hash+suffix
            src=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=source_fd)
            try:
                info=os.fstat(src)
                if not stat.S_ISREG(info.st_mode) or info.st_nlink!=1 or info.st_size>_MAX_PACK+4*1024*1024:
                    raise PermissionError('Invalid quarantined pack component')
                temp='.agentporter-fetch-'+uuid.uuid4().hex
                dst=os.open(temp,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600,dir_fd=target_fd)
                try:
                    remaining=info.st_size
                    while remaining:
                        chunk=os.read(src,min(65536,remaining))
                        if not chunk: raise PermissionError('Truncated quarantined pack component')
                        view=memoryview(chunk)
                        while view:
                            view=view[os.write(dst,view):]
                        remaining-=len(chunk)
                    os.fsync(dst)
                finally: os.close(dst)
                try:
                    os.link(temp,name,src_dir_fd=target_fd,dst_dir_fd=target_fd,follow_symlinks=False)
                except FileExistsError:
                    existing=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=target_fd)
                    try:
                        if os.fstat(existing).st_size!=info.st_size: raise PermissionError('Conflicting canonical Git pack')
                        os.lseek(src,0,os.SEEK_SET)
                        os.lseek(existing,0,os.SEEK_SET)
                        a=hashlib.sha256(); b=hashlib.sha256()
                        while True:
                            ca=os.read(src,65536); cb=os.read(existing,65536)
                            if not ca and not cb: break
                            a.update(ca); b.update(cb)
                        if a.digest()!=b.digest(): raise PermissionError('Conflicting canonical Git pack')
                    finally: os.close(existing)
                finally:
                    os.unlink(temp,dir_fd=target_fd)
                os.fsync(target_fd)
            finally: os.close(src)
        finally:
            os.close(source_fd); os.close(target_fd)
        os.fsync(objects_fd); os.fsync(metadata_fd)
    finally:
        os.close(objects_fd)


class ApprovedGitFetches:
    def __init__(self, registry,sandbox,authority,manager):
        self.registry,self.sandbox,self.authority,self.manager=registry,sandbox,authority,manager
        self.verifier=authority.verifier
        self._require_runtime()

    def _require_runtime(self):
        if (self.sandbox.transactional_writes is not True or self.sandbox.resources is None
            or self.manager.resources is not self.sandbox.resources
            or Path(self.manager.state_dir).resolve()!=Path(self.sandbox.state_dir).resolve()):
            raise PermissionError('Approved fetch requires shared supervised runtime and admission')

    def _proposal(self,workspace_id,remote_id,ref,state,grant,broker):
        p=state.to_payload(); tracking=_validate_tracking_ref(remote_id,ref)
        ad=broker.discover('git-upload-pack')
        remote_oid=ad.refs.get(ref)
        if remote_oid is None or len(remote_oid)!=len(p['expected_tree']):
            raise PermissionError('Protected remote branch is absent or uses another object format')
        algorithm='sha256' if len(remote_oid)==64 else 'sha1'
        old=_tracking_tip(self.sandbox,self.registry.get(workspace_id).path,tracking,algorithm)
        if old==remote_oid: raise PermissionError('Local tracking ref already matches remote')
        pack=broker.fetch_pack(ref,remote_oid); validate_pack(pack,algorithm)
        params={'remote_id':remote_id,'remote_url':grant.repository.url,'remote_ref':ref,
            'remote_oid':remote_oid,'tracking_ref':tracking,'old_oid':old,'new_oid':remote_oid,
            'pack_sha256':hashlib.sha256(pack).hexdigest(),'pack_size':len(pack),
            'policy_sha256':self.authority.policy_sha256}
        return GitApprovalRequest.from_payload({**p,'operation':'fetch','parameters':params}),pack

    def prepare(self,workspace_id,remote_id,ref):
        self._require_runtime()
        with synchronous_slot(self.manager):
            grant,broker=self.authority.authorize(workspace_id,remote_id,ref,'fetch')
            with locked_git_request(self.registry,self.sandbox,workspace_id,'fetch',{}) as state:
                return self._proposal(workspace_id,remote_id,ref,state,grant,broker)[0]

    def fetch(self,workspace_id,remote_id,ref,receipt):
        self._require_runtime()
        with execution_slot(self.manager) as token:
            guarded=False
            guard=None
            try:
                grant,broker=self.authority.authorize(workspace_id,remote_id,ref,'fetch')
                with locked_git_request(self.registry,self.sandbox,workspace_id,'fetch',{}) as state:
                    request,pack=self._proposal(workspace_id,remote_id,ref,state,grant,broker)
                    p=request.to_payload(); params=p['parameters']; transactions=Path(self.sandbox.state_dir)/'workspace-transactions'
                    approval=self.verifier.verify_and_consume(receipt,request)
                    info=Path(p['repository_path']).stat()
                    guard=transactions/(workspace_key(info)+'.git-pending.json')
                    guard_document={'version':2,'request':p,'request_sha256':request.digest,
                        'approval_nonce':approval.nonce,'admission_token':token}
                    try:
                        _write_fetch_guard(guard,guard_document)
                        guarded=True
                    except BaseException:
                        try:
                            os.stat(guard,follow_symlinks=False)
                            guarded=True
                        except FileNotFoundError:
                            pass
                        raise
                    bind(self.manager,token,request.digest,guard)
                    _,broker=self.authority.authorize(workspace_id,remote_id,ref,'fetch')
                    if self.authority.policy_sha256!=params['policy_sha256']:
                        raise PermissionError('Fetch policy changed after approval')
                    if hashlib.sha256(pack).hexdigest()!=params['pack_sha256'] or len(pack)!=params['pack_size']:
                        raise PermissionError('Fetch pack differs from signed request')
                    algorithm='sha256' if len(params['remote_oid'])==64 else 'sha1'
                    validate_pack(pack,algorithm)
                    with tempfile.TemporaryDirectory(prefix='agentporter-fetch-') as directory:
                        input_path=Path(directory)/'input'; input_path.write_bytes(pack); input_path.chmod(0o400)
                        out=Path(directory)/'out'; out.mkdir(mode=0o700)
                        mount=_MetadataMount(p)
                        input_fd=os.open(input_path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
                        out_fd=os.open(out,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
                        mount._fds.extend((input_fd,out_fd))
                        try:
                            original=mount.wrap_command
                            metadata_writable = False
                            def wrap(command):
                                command=original(command)
                                git_index=command.index(f'/proc/self/fd/{mount.git}')
                                command[git_index-1]='--bind' if metadata_writable else '--ro-bind'
                                return command+['--ro-bind',f'/proc/self/fd/{input_fd}','/in/pack','--bind',f'/proc/self/fd/{out_fd}','/out']
                            mount.wrap_command=wrap
                            result=self.sandbox._run_command(workspace_path=p['repository_path'],
                                argv=['/usr/bin/python3','-I','-S','-c',_INDEX,request.canonical_payload.decode(),_INSPECT,params['remote_oid']],
                                writable=False,git_metadata_writable=True,network_access=False,workspace_transaction=mount,
                                require_resources=True,timeout_seconds=90,max_output_bytes=8192)
                            pack_hash=result['stdout'].strip()
                            if result['exit_code'] or len(pack_hash)!=len(params['remote_oid']) or any(c not in '0123456789abcdef' for c in pack_hash):
                                raise PermissionError('Quarantined fetch validation failed')
                            _same_identity(mount.workspace,mount.root); _same_identity(mount.workspace/'.git',mount.git)
                            _promote_quarantine(mount.git,out,pack_hash)
                            # Ref compare-and-swap runs offline under the same lease and resource supervisor.
                            metadata_writable = True
                            result=self.sandbox._run_command(workspace_path=p['repository_path'],
                                argv=['/usr/bin/python3','-I','-S','-c',_UPDATE,request.canonical_payload.decode(),_INSPECT],
                                writable=False,git_metadata_writable=True,network_access=False,workspace_transaction=mount,
                                require_resources=True,timeout_seconds=20,max_output_bytes=1024)
                            if result['exit_code'] or result['stdout'].strip()!=params['remote_oid']:
                                raise ResourceCleanupError('Fetch tracking ref outcome requires owner recovery; guard retained')
                            receipts=transactions/'git-fetch-receipts'; receipts.mkdir(mode=0o700,exist_ok=True)
                            from agentporter.sandbox.workspace_recovery import _directory
                            _directory(receipts,private=True)
                            _write_private(receipts/(approval.nonce+'.json'),{'version':1,'request':p,
                                'request_sha256':request.digest,'approval_nonce':approval.nonce,'tracking_ref_updated':True})
                            _sync(transactions); resolve(self.manager,token); guard.unlink(); _sync(transactions)
                            return params['remote_oid']
                        finally: mount.close()
            except BaseException:
                if not guarded and guard is not None:
                    try:
                        os.stat(guard,follow_symlinks=False)
                        guarded=True
                    except FileNotFoundError:
                        pass
                if guarded: raise ResourceCleanupError('Approved fetch requires owner reconciliation; guard retained') from None
                resolve(self.manager,token); raise
