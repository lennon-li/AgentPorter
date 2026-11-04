"""Fixed offline pull integration in an existing private workspace transaction.

This is deliberately not an approved-pull backend. The trusted caller must first
validate/import the pack and consume the signed plan, and must discard failures.
Nothing here acquires a second lease, updates tracking refs, or publishes files.
"""
import json
import os

from agentporter.git_approval_state import _INSPECT
from agentporter.sandbox.workspace_transactions import WorkspaceTransaction

_MODES = frozenset({'ff-only', 'merge', 'rebase'})

# Standalone because the sandbox intentionally cannot import the host package.
_PROGRAM = r'''
import contextlib, hashlib, io, json, os, pathlib, stat, subprocess, sys, tempfile
request = json.loads(sys.argv[1])
root = pathlib.Path('/workspace') / request.get('repository_relative','.')
fd=os.open('/workspace',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
try:
 for component in (() if request.get('repository_relative','.')=='.' else request['repository_relative'].split('/')):
  child=os.open(component,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd);os.close(fd);fd=child
 metadata=os.stat('.git',dir_fd=fd,follow_symlinks=False)
 if [metadata.st_dev,metadata.st_ino]!=request['private_metadata_identity']:raise RuntimeError('Selected private metadata changed')
finally:os.close(fd)
if 'private_config_sha256' in request and hashlib.sha256((root/'.git/config').read_bytes()).hexdigest()!=request['private_config_sha256']:raise RuntimeError('Selected configuration differs from sealed host config')
try:
 check=os.open(root/'.git/config',os.O_WRONLY|os.O_NOFOLLOW)
except OSError as error:
 if error.errno!=30:raise RuntimeError('Selected configuration does not prove read-only mount')
else:
 os.close(check);raise RuntimeError('Selected configuration is not sealed read-only')
os.chdir(root)
env = {
 'PATH':'/usr/bin:/bin','LANG':'C','LC_ALL':'C','HOME':'/nonexistent',
 'GIT_CONFIG_NOSYSTEM':'1','GIT_CONFIG_GLOBAL':'/dev/null',
 'GIT_NO_REPLACE_OBJECTS':'1','GIT_NO_LAZY_FETCH':'1','GIT_ALLOW_PROTOCOL':'',
 'GIT_TERMINAL_PROMPT':'0','GIT_OPTIONAL_LOCKS':'0','GIT_ATTR_NOSYSTEM':'1',
 'GIT_DIR':str(root/'.git'),'GIT_WORK_TREE':str(root),'GIT_GRAFT_FILE':'/dev/null',
 'GIT_EDITOR':'/bin/false','GIT_SEQUENCE_EDITOR':'/bin/false',
 'GIT_MERGE_AUTOEDIT':'no','GIT_PAGER':'cat',
 'GIT_AUTHOR_NAME':'AgentPorter','GIT_AUTHOR_EMAIL':'agents@agentporter.invalid',
 'GIT_COMMITTER_NAME':'AgentPorter','GIT_COMMITTER_EMAIL':'agents@agentporter.invalid',
}
base = ['/usr/bin/git','-c','safe.directory='+str(root),
 '-c','core.hooksPath=/dev/null','-c','core.fsmonitor=false',
 '-c','core.attributesFile=/dev/null','-c','protocol.allow=never',
 '-c','credential.helper=','-c','commit.gpgSign=false','-c','tag.gpgSign=false',
 '-c','merge.gpgSign=false','-c','merge.verifySignatures=false',
 '-c','merge.autoStash=false','-c','rebase.autoStash=false',
 '-c','rebase.autoSquash=false','-c','rebase.updateRefs=false',
 '-c','rebase.rebaseMerges=false','-c','rebase.missingCommitsCheck=error',
 '-c','rerere.enabled=false','-c','submodule.recurse=false',
 '-c','fetch.recurseSubmodules=false','-c','maintenance.auto=false',
 '-c','gc.auto=0']
def run(args, statuses=(0,), limit=4*1024*1024):
 with tempfile.TemporaryFile() as output:
  result = subprocess.run(base+args,cwd=root,env=env,stdin=subprocess.DEVNULL,
   stdout=output,stderr=subprocess.DEVNULL,timeout=45,check=False)
  if output.tell()>limit: raise RuntimeError('Private Git output exceeds budget')
  output.seek(0); data=output.read(limit+1)
 if result.returncode not in statuses: raise RuntimeError('Private Git operation failed')
 return result.returncode,data

def text(args, statuses=(0,)):
 return run(args,statuses,65536)[1].decode('utf-8').strip()

kind=text(['rev-parse','--show-object-format'])
if kind not in ('sha1','sha256'): raise RuntimeError('Unsupported object format')
width=40 if kind=='sha1' else 64
def oid(value):
 return isinstance(value,str) and len(value)==width and all(c in '0123456789abcdef' for c in value) and value!='0'*width

def worktree_digest():
 digest=hashlib.sha256(); remaining=[100000,256*1024*1024]
 def scan(directory,relative='',depth=0):
  if depth>128: raise RuntimeError('Worktree depth exceeds budget')
  for entry in sorted(os.scandir(directory),key=lambda e:os.fsencode(e.name)):
   if not relative and entry.name=='.git': continue
   name=relative+entry.name
   if name in request['masked']: continue
   remaining[0]-=1
   if remaining[0]<0: raise RuntimeError('Worktree entries exceed budget')
   info=entry.stat(follow_symlinks=False)
   digest.update(os.fsencode(name)+b'\0'+str(stat.S_IMODE(info.st_mode)).encode()+b'\0')
   if stat.S_ISDIR(info.st_mode):
    digest.update(b'd\0'); scan(entry.path,name+'/',depth+1)
   elif stat.S_ISLNK(info.st_mode):
    digest.update(b'l\0'+os.fsencode(os.readlink(entry.path))+b'\0')
   elif stat.S_ISREG(info.st_mode) and info.st_nlink==1:
    remaining[1]-=info.st_size
    if info.st_size>64*1024*1024 or remaining[1]<0: raise RuntimeError('Worktree bytes exceed budget')
    digest.update(b'f\0'+str(info.st_size).encode()+b'\0')
    fd=os.open(entry.path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
    try:
     pinned=os.fstat(fd)
     if (pinned.st_dev,pinned.st_ino)!=(info.st_dev,info.st_ino): raise RuntimeError('Worktree inode changed')
     left=info.st_size
     while left:
      chunk=os.read(fd,min(65536,left))
      if not chunk: raise RuntimeError('Worktree changed during inspection')
      digest.update(chunk);left-=len(chunk)
     after=os.fstat(fd)
     if (info.st_size,info.st_mtime_ns,info.st_ctime_ns)!=(after.st_size,after.st_mtime_ns,after.st_ctime_ns):
      raise RuntimeError('Worktree changed during inspection')
    finally: os.close(fd)
   else: raise RuntimeError('Unsupported worktree entry')
 scan(root)
 return digest.hexdigest()

def metadata_digest(relative, limit, optional=False):
 try: fd=os.open(root/'.git'/relative,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
 except FileNotFoundError:
  if optional: return None
  raise
 try:
  info=os.fstat(fd)
  if not stat.S_ISREG(info.st_mode) or info.st_nlink!=1 or info.st_size>limit:
   raise RuntimeError('Unsupported private Git control file')
  raw=os.read(fd,limit+1)
  after=os.fstat(fd)
  if len(raw)!=info.st_size or (info.st_size,info.st_mtime_ns,info.st_ctime_ns)!=(after.st_size,after.st_mtime_ns,after.st_ctime_ns):
   raise RuntimeError('Private Git control file changed during inspection')
  return hashlib.sha256(raw).hexdigest()
 finally: os.close(fd)

def state():
 branch=text(['symbolic-ref','--quiet','HEAD'],(0,1)) or None
 head=text(['rev-parse','--verify','HEAD'])
 if not oid(head): raise RuntimeError('Pull requires a committed HEAD')
 unmerged=bool(run(['ls-files','--unmerged','-z'])[1])
 tree=None
 if not unmerged:
  namespace={}
  with contextlib.redirect_stdout(io.StringIO()): exec(_BOUND_INSPECT_SOURCE_.replace('/workspace',str(root)),namespace)
  if namespace['head']!=head or namespace['branch']!=branch: raise RuntimeError('Private Git state changed during inspection')
  tree=namespace['tree']
 refs=text(['for-each-ref','--format=%(refname)%00%(objectname)%00%(symref)'])
 index=root/'.git/index'
 with index.open('rb') as source:
  raw=source.read(64*1024*1024+1)
 if len(raw)>64*1024*1024: raise RuntimeError('Index exceeds budget')
 return {'head':head,'branch':branch,'tree':tree,'object_format':kind,
  'index_sha256':hashlib.sha256(raw).hexdigest(),
  'head_sha256':metadata_digest('HEAD',4096),
  'stash_log_sha256':metadata_digest('logs/refs/stash',16384,True),
  'worktree_sha256':worktree_digest(),'refs_sha256':hashlib.sha256(refs.encode()).hexdigest(),
  'unmerged':unmerged}

before=state()
before_refs=text(['for-each-ref','--format=%(refname)%00%(objectname)%00%(symref)']).splitlines()
if request['action']=='inspect':
 print(json.dumps(before,sort_keys=True));sys.exit(0)
if request['action']!='integrate' or request['mode'] not in ('ff-only','merge','rebase'):
 raise RuntimeError('Invalid private pull action')
if before!=request['expected']: raise RuntimeError('Private pull baseline changed')
if before['branch'] is None or before['unmerged']: raise RuntimeError('Pull requires a resolved local branch')
# In-progress sequencers and untrusted saved rebase todo/exec instructions are
# never resumed, continued, or interpreted. Even an apparently completed one
# requires a separate owner recovery decision.
for name in ('MERGE_HEAD','CHERRY_PICK_HEAD','REVERT_HEAD','rebase-merge','rebase-apply','sequencer','BISECT_LOG'):
 if os.path.lexists(root/'.git'/name): raise RuntimeError('Repository has an operation in progress')
remote=request['remote_oid'];mode=request['mode']
if not oid(remote) or text(['cat-file','-t',remote])!='commit': raise RuntimeError('Remote target is not a commit')
run(['fsck','--strict','--no-reflogs','--connectivity-only',remote])
ff=run(['merge-base','--is-ancestor',before['head'],remote],(0,1))[0]==0
already=run(['merge-base','--is-ancestor',remote,before['head']],(0,1))[0]==0
reason=None
# Include ignored files: native checkout may otherwise overwrite them. Refuse
# both file/directory directions before rebase refreshes the private index.
if not already:
 untracked=run(['ls-files','--others','-z'])[1].split(b'\0')
 incoming=run(['ls-tree','-r','--name-only','-z',remote])[1].split(b'\0')
 untracked=[path for path in untracked if path]
 incoming=[path for path in incoming if path]
 if len(untracked)+len(incoming)>100000: raise RuntimeError('Checkout paths exceed budget')
 # Prefix lookup avoids a quadratic comparison of large repository trees.
 incoming_set=set(incoming)
 incoming_parents=set()
 for path in incoming:
  parts=path.split(b'/')
  for count in range(1,len(parts)): incoming_parents.add(b'/'.join(parts[:count]))
 for path in untracked:
  parts=path.split(b'/')
  if path in incoming_set or path in incoming_parents or any(b'/'.join(parts[:count]) in incoming_set for count in range(1,len(parts))):
   reason='untracked_collision';break
if mode=='ff-only' and not (ff or already): reason='diverged'
# Native merge can silently include unrelated staged edits in its merge
# commit. Refuse this case; a pull must not commit the owner's staged work.
staged=run(['diff-index','--cached','--quiet',before['head'],'--'],(0,1))[0]!=0
# Overlay stat identity differs from the canonical cache. Refresh a scratch
# copy only after the exact signed baseline matches; a refusal must retain the
# original private index bytes/flags. Native Git refreshes it on integration.
with tempfile.TemporaryDirectory(prefix='pull-index-check-',dir='/tmp') as scratch_index:
 scratch=pathlib.Path(scratch_index)/'index';budget=64*1024*1024;shared_count=0
 def copy_checked(source,target):
  global budget
  fd=os.open(source,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
  try:
   info=os.fstat(fd)
   if not stat.S_ISREG(info.st_mode) or info.st_nlink!=1 or info.st_size>budget:raise RuntimeError('Scratch index exceeds budget')
   budget-=info.st_size
   with os.fdopen(os.dup(fd),'rb') as incoming,open(target,'xb') as outgoing:
    left=info.st_size
    while left:
     data=incoming.read(min(65536,left))
     if not data:raise RuntimeError('Scratch index changed')
     outgoing.write(data);left-=len(data)
    if incoming.read(1):raise RuntimeError('Scratch index grew')
  finally:os.close(fd)
 copy_checked(root/'.git/index',scratch)
 for entry in (root/'.git').iterdir():
  if entry.name.startswith('sharedindex.'):
   shared_count+=1
   if shared_count>128:raise RuntimeError('Scratch shared indexes exceed budget')
   copy_checked(entry,pathlib.Path(scratch_index)/entry.name)
 env['GIT_INDEX_FILE']=str(scratch)
 try:
  run(['update-index','--really-refresh'],(0,1))
  unstaged=run(['diff-files','--quiet','--'],(0,1))[0]!=0
 finally:del env['GIT_INDEX_FILE']
if not already and mode=='merge' and not ff and staged: reason='dirty_index'
if not already and mode=='rebase' and (staged or unstaged): reason='dirty_index' if staged else 'dirty_worktree'
if reason:
 print(json.dumps({'status':'refused','reason':reason,'mode':mode,'remote_oid':remote,
  'private_only':True,'before':before,'after':state()},sort_keys=True));sys.exit(0)
if already:
 status=0
elif mode=='rebase':
 status=run(['rebase','--no-verify','--no-autostash','--no-autosquash','--no-rebase-merges',
  '--no-fork-point','--no-gpg-sign','--strategy=ort',remote],(0,1,128))[0]
else:
 args=['merge','--no-verify','--no-edit','--no-gpg-sign','--no-autostash',
  '--strategy=ort','--ff-only' if mode=='ff-only' else '--ff','--',remote]
 status=run(args,(0,1,128))[0]
after=state()
if after['branch'] != before['branch'] and status==0:
 raise RuntimeError('Private pull changed branch identity')
def other_refs(lines):
 return [line for line in lines if line.split('\0',1)[0]!=before['branch']]
after_refs=text(['for-each-ref','--format=%(refname)%00%(objectname)%00%(symref)']).splitlines()
if other_refs(before_refs)!=other_refs(after_refs):
 raise RuntimeError('Private pull changed another ref')
outcome='integrated' if status==0 else ('conflict' if after['unmerged'] else 'refused')
print(json.dumps({'status':outcome,'reason':None if status==0 else ('content_conflict' if after['unmerged'] else 'git_refused'),
 'mode':mode,'remote_oid':remote,'private_only':True,'before':before,'after':after},sort_keys=True))
'''
_PROGRAM = _PROGRAM.replace('_BOUND_INSPECT_SOURCE_', repr(_INSPECT))


from agentporter.sandbox.workspace_git_runtime import (FixedGitProgram,fixed_runtime_command,runtime_script,parse_runtime_output)
_RUNTIME_EXECUTOR=runtime_script(FixedGitProgram.PULL)

class _PullMount:
    """Seal config independently of any prior worker changes in private metadata."""
    wrap_argv = staticmethod(WorkspaceTransaction.wrap_argv)

    def __init__(self, transaction, history, repository='.',*,live_view=False):
        self.transaction, self.history, self.repository = transaction, history, repository
        self.live_view=live_view

    @property
    def sandbox_workspace_fd(self):return self.transaction.inspection_fd

    @property
    def launch_fds(self):
        return (*self.transaction.launch_fds,self.history.mount.config,
                *((self.transaction._runtime_view_fd,*self.transaction._runtime_namespace_fds)
                  if self.live_view and self.transaction._runtime_view_fd is not None else ()))

    def wrap_command(self, command):
        if self.live_view and self.transaction._runtime_view_fd is not None:
            return list(command)  # The fixed launcher below enters only the job-bound merged view.
        command=list(command)
        source=f'/proc/self/fd/{self.sandbox_workspace_fd}/.'
        for index in range(len(command)-2):
            if command[index:index+3]==['--ro-bind',source,'/workspace']:
                command[index+1]=str(self.transaction.workspace)
        command=self.transaction.wrap_command(command)
        fd = self.history.mount.config
        os.lseek(fd, 0, os.SEEK_SET)
        target='/workspace' if self.repository=='.' else '/workspace/'+self.repository
        command += ['--ro-bind-data', str(fd),target+'/.git/config']
        return command

    def wrap_launcher(self,command):
        if not self.live_view or self.transaction._runtime_view_fd is None:return command
        tail=command[command.index('--')+1:]
        prefix=WorkspaceTransaction.wrap_argv([])
        if tail[:len(prefix)]!=prefix:raise PermissionError('Expected the fixed descriptor closer')
        argv=tail[len(prefix):]
        if len(argv)!=6 or argv[:5]!=['/usr/bin/python3','-I','-S','-c',_PROGRAM]:
            raise PermissionError('Only the fixed offline integration program may enter the live view')
        return fixed_runtime_command(self.transaction,FixedGitProgram.PULL,argv[5])


class PrivateGitPullIntegration:
    """Use the transaction's existing lease and never publish its candidate."""
    def __init__(self, sandbox):
        self.sandbox = sandbox

    def _run(self, transaction, request, repository='.'):
        if not isinstance(transaction, WorkspaceTransaction):
            raise PermissionError('Pull integration requires a native private transaction')
        if (transaction._closed or transaction._applied or not transaction.writable
                or self.sandbox.transactional_writes is not True or self.sandbox.resources is None):
            raise PermissionError('Pull integration requires a live supervised writable transaction')
        transaction._check_root_identity()
        from agentporter.git_remote_policy import repository_relative
        repository=repository_relative(repository)
        key='.git' if repository=='.' else repository+'/.git'
        history = transaction.git_histories.get(key)
        if history is None:
            raise PermissionError('Pull integration requires its exact preexisting private repository')
        if history.sandbox is not self.sandbox:
            raise PermissionError('Pull transaction uses a different sandbox')
        from agentporter.git_commits import _inspect_metadata, _mount_id
        metadata_fd = os.open(history.private, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            _inspect_metadata(metadata_fd, _mount_id(metadata_fd))
        finally:
            os.close(metadata_fd)
        import hashlib
        if transaction._runtime_view_fd is not None:
            config_digest=hashlib.sha256(history.clean_config.read_bytes()).hexdigest()
        else:
            os.lseek(history.mount.config,0,os.SEEK_SET);config_digest=hashlib.sha256(os.read(history.mount.config,8192)).hexdigest()
        request = {**request,'private_config_sha256':config_digest, 'repository_relative':repository,'private_metadata_identity':[history.private.stat().st_dev,history.private.stat().st_ino], 'masked': [relative if repository=='.' else relative[len(repository)+1:] for relative, _ in transaction.masks if repository=='.' or relative.startswith(repository+'/')]}
        result = self.sandbox._run_command(workspace_path=str(transaction.workspace),
            argv=['/usr/bin/python3', '-I', '-S', '-c', _PROGRAM, json.dumps(request)],
            writable=True, git_metadata_writable=False, network_access=False,
            workspace_transaction=_PullMount(transaction, history,repository,live_view=True),
            timeout_seconds=120, max_output_bytes=65536, require_resources=True)
        transaction._check_root_identity()
        if result['exit_code']:
            raise PermissionError('Private offline pull integration failed; discard transaction')
        try:
            output=result['stdout']
            if transaction._runtime_view_fd is not None:
                proof,output=parse_runtime_output(output)
                self.last_runtime_proof=proof
            return json.loads(output)
        except (ValueError, TypeError) as error:
            raise PermissionError('Private pull returned invalid state; discard transaction') from error

    def inspect(self, transaction, *, repository='.'):
        """Bind private HEAD, index bytes/tree, refs and ordinary worktree bytes."""
        return self._run(transaction, {'action': 'inspect'},repository)

    def run(self, transaction, remote_oid, mode, *, expected, repository='.'):
        if not isinstance(mode, str) or mode not in _MODES:
            raise ValueError('Invalid exact pull mode')
        if (not isinstance(remote_oid, str) or len(remote_oid) not in (40, 64)
                or any(c not in '0123456789abcdef' for c in remote_oid)):
            raise ValueError('Invalid exact remote commit')
        if not isinstance(expected, dict):
            raise ValueError('Expected private pull baseline is required')
        return self._run(transaction, {'action': 'integrate', 'remote_oid': remote_oid,
                                      'mode': mode, 'expected': expected},repository)
