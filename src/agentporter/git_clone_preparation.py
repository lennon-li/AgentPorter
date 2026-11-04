"""Offline clone acquisition and fixed-program private materialization.

Only the authoritative job adapter may attach a consumed clone birth capability.
Normal quiescent finalization owns all canonical publication and recovery.
"""
from dataclasses import dataclass
import hashlib,json,os,re,tempfile
from pathlib import Path,PurePosixPath
from agentporter.git_approvals import GitApprovalRequest
from agentporter.git_smart_http import RemoteRepository,validate_pack,_ref
from agentporter.sandbox.workspace_delta import _require_public_path
from agentporter.sandbox.workspace_transactions import WorkspaceTransaction
from agentporter.sandbox.repository_birth import _canonical_info,_canonical_dir_fd
from agentporter.sandbox.workspace_directories import _directory_record


@dataclass(frozen=True)
class CloneScope:
    workspace_id:str
    workspace_path:str
    repository:str
    remote_id:str
    remote_url:str
    remote_ref:str
    local_branch:str
    policy_sha256:str

    def __post_init__(self):
        if not re.fullmatch('[A-Za-z0-9_-]{1,128}',self.workspace_id):raise ValueError('One workspace required')
        path=PurePosixPath(self.workspace_path)
        if not path.is_absolute() or str(path)!=self.workspace_path or '..'in path.parts:raise ValueError('Canonical parent workspace required')
        target=PurePosixPath(self.repository)
        if target.is_absolute() or str(target)!=self.repository or any(x in ('','.','..') for x in target.parts) or self.repository=='.':raise ValueError('Exact nested clone target required')
        _require_public_path(self.repository)
        if not re.fullmatch('[A-Za-z0-9_-]{1,128}',self.remote_id) or not _ref(self.remote_ref,branch=True) or not _ref(self.local_branch,branch=True):raise ValueError('Exact remote/ref/branch required')
        RemoteRepository(self.remote_url)
        if not re.fullmatch('[0-9a-f]{64}',self.policy_sha256):raise ValueError('Exact owner policy digest required')


_PROGRAM=r'''
import hashlib,json,os,pathlib,subprocess,sys,tempfile
request=json.loads(sys.argv[1])
env={'PATH':'/usr/bin:/bin','HOME':'/nonexistent','LANG':'C','LC_ALL':'C',
 'GIT_CONFIG_NOSYSTEM':'1','GIT_CONFIG_GLOBAL':'/dev/null','GIT_ALLOW_PROTOCOL':'',
 'GIT_TERMINAL_PROMPT':'0','GIT_NO_LAZY_FETCH':'1','GIT_NO_REPLACE_OBJECTS':'1'}
base=['/usr/bin/git','-c','safe.directory=/workspace','-c','core.hooksPath=/dev/null',
 '-c','core.fsmonitor=false','-c','protocol.allow=never','-c','submodule.recurse=false',
 '-c','fetch.recurseSubmodules=false','-c','core.attributesFile=/dev/null',
 '-c','core.autocrlf=false','-c','maintenance.auto=false','-c','gc.auto=0']
def run(args,input=None,source=None,limit=1048576):
 with tempfile.TemporaryFile() as output:
  result=subprocess.run(base+args,env=env,input=input,stdin=source,stdout=output,
   stderr=subprocess.DEVNULL,timeout=45,check=False)
  if result.returncode or output.tell()>limit:raise RuntimeError('Private clone graph command failed')
  output.seek(0);return output.read(limit+1)
target=pathlib.Path('/workspace')
if 'repository' in request:
 parts=request['repository'].split('/')
 if any(x in ('','.','..','.git') for x in parts):raise RuntimeError('Invalid fixed clone target')
 for part in parts:
  target=target/part
  if target.is_symlink():raise RuntimeError('Clone target is a symlink')
  target.mkdir(exist_ok=True)
os.chdir(target)
if any(target.iterdir()):raise RuntimeError('Private clone candidate is not empty')
if 'pack_sha256' in request and hashlib.sha256(pathlib.Path('/tmp/incoming.pack').read_bytes()).hexdigest()!=request['pack_sha256']:raise RuntimeError('Clone pack changed')
run(['init','--quiet','--template=','--object-format='+request['object_format'],
 '--initial-branch='+request['branch'].removeprefix('refs/heads/')])
empty_tree=run(['hash-object','-t','tree','--stdin'],input=b'').decode().strip()
with open('/tmp/incoming.pack','rb') as pack:run(['index-pack','--stdin','--strict','--fix-thin'],source=pack)
if run(['cat-file','-t',request['remote_oid']]).strip()!=b'commit':raise RuntimeError('Clone remote must name a commit')
run(['rev-list','--objects','--missing=error',request['remote_oid']],limit=4*1024*1024)
run(['update-ref','--no-deref',request['branch'],request['remote_oid'],'0'*len(request['remote_oid'])])
run(['symbolic-ref','HEAD',request['branch']])
run(['reset','--hard','--no-recurse-submodules',request['remote_oid']])
if 'remote_id' in request:
 run(['config','remote.'+request['remote_id']+'.url',request['remote_url']])
 run(['config','remote.'+request['remote_id']+'.fetch','+'+request['remote_ref']+':'+request['tracking_ref']])
 run(['config','branch.'+request['branch'].removeprefix('refs/heads/')+'.remote',request['remote_id']])
 run(['config','branch.'+request['branch'].removeprefix('refs/heads/')+'.merge',request['remote_ref']])
 run(['update-ref','--no-deref',request['tracking_ref'],request['remote_oid'],'0'*len(request['remote_oid'])])
run(['fsck','--strict','--no-reflogs'])
print(json.dumps({'initial_tree':empty_tree,'head':run(['rev-parse','HEAD']).decode().strip(),
 'tree':run(['rev-parse','HEAD^{tree}']).decode().strip(),'branch':run(['symbolic-ref','HEAD']).decode().strip()}))
'''


class _PackMount:
    wrap_argv=staticmethod(WorkspaceTransaction.wrap_argv)
    def __init__(self,fd):self.launch_fds=(fd,);self.fd=fd
    def wrap_command(self,command):return list(command)+['--ro-bind','/proc/self/fd/'+str(self.fd),'/tmp/incoming.pack']


def target_before(transaction,scope):
    if str(transaction.workspace)!=scope.workspace_path or transaction._closed or transaction._applied or not transaction.writable or not transaction._allow_git_birth:
        raise PermissionError('Clone requires the exact writable host-authorized parent transaction')
    transaction._check_root_identity()
    pieces=PurePosixPath(scope.repository).parts
    parent=os.fstat(transaction._root_fd)
    for count in range(1,len(pieces)+1):
        relative='/'.join(pieces[:count]);info=_canonical_info(transaction,relative)
        if info is None:return {'kind':'absent','first_missing':relative,'parent_device':parent.st_dev,'parent_inode':parent.st_ino}
        if not __import__('stat').S_ISDIR(info.st_mode):raise PermissionError('Clone target crosses a non-directory parent')
        parent=info
    fd=_canonical_dir_fd(transaction,scope.repository)
    try:
        expected=transaction._birth_empty_directories.get(scope.repository)
        if expected is None or _directory_record(fd,'.')!=expected:raise PermissionError('Clone target is not its original empty directory')
        with os.scandir(fd) as entries:
            if next(entries,None)is not None:raise PermissionError('Clone target is not empty')
        return {'kind':'empty','directory':expected}
    finally:os.close(fd)


def _job_context(transaction,value):
    from agentporter.agents.roster import PUBLIC_AGENT_IDS
    names={'job_id','agent','admission_token','transaction_directory','transaction_device','transaction_inode'}
    info=transaction.directory.stat()
    if (not isinstance(value,dict) or set(value)!=names
            or not isinstance(value['job_id'],str) or not re.fullmatch('job_[0-9a-f]{24}',value['job_id'])
            or value['agent']not in PUBLIC_AGENT_IDS
            or not isinstance(value['admission_token'],str) or not re.fullmatch('[0-9a-f]{32}',value['admission_token'])
            or value['transaction_directory']!=str(transaction.directory)
            or type(value['transaction_device'])is not int or type(value['transaction_inode'])is not int
            or (value['transaction_device'],value['transaction_inode'])!=(info.st_dev,info.st_ino)):
        raise PermissionError('Exact service-issued clone job/transaction context required')
    return dict(value)


def prepare_clone(transaction,sandbox,scope,broker,*,job_context):
    """Return a signed-request-shaped PRIVATE candidate, never canonical writes."""
    if not isinstance(scope,CloneScope):raise PermissionError('Trusted clone scope required')
    if sandbox.resources is None:raise PermissionError('Clone preparation requires supervised resources')
    job_context=_job_context(transaction,job_context)
    before=target_before(transaction,scope)
    advertisement=broker.discover('git-upload-pack');kind=advertisement.object_format
    if kind not in ('sha1','sha256'):raise PermissionError('Unsupported clone object format')
    remote_oid=advertisement.refs.get(scope.remote_ref);width=40 if kind=='sha1' else 64
    if not isinstance(remote_oid,str) or not re.fullmatch('[0-9a-f]{'+str(width)+'}',remote_oid) or set(remote_oid)=={'0'}:raise PermissionError('Exact advertised clone commit is absent')
    pack=broker.fetch_pack(scope.remote_ref,remote_oid)
    if not isinstance(pack,bytes) or not 1<=len(pack)<=64*1024*1024-65520:raise PermissionError('Clone acquisition exceeds bound')
    validate_pack(pack,kind)
    if target_before(transaction,scope)!=before:raise PermissionError('Clone target changed during acquisition')
    work=Path(tempfile.mkdtemp(prefix='clone-prepare-',dir=transaction.directory));candidate=work/'candidate';candidate.mkdir(mode=0o700)
    source=work/'input.pack';fd=os.open(source,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o400)
    with os.fdopen(fd,'wb') as output:output.write(pack);output.flush();os.fsync(output.fileno())
    fd=os.open(source,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        result=sandbox._run_command(workspace_path=str(candidate),argv=['/usr/bin/python3','-I','-S','-c',_PROGRAM,
            json.dumps({'object_format':kind,'remote_oid':remote_oid,'branch':scope.local_branch})],
            writable=True,git_metadata_writable=True,network_access=False,workspace_transaction=_PackMount(fd),
            require_resources=True,timeout_seconds=90,max_output_bytes=8192)
    finally:os.close(fd)
    if result['exit_code']:raise PermissionError('Private clone graph validation failed: '+result['stderr'][-500:])
    state=json.loads(result['stdout']);root=os.fstat(transaction._root_fd);private=candidate.stat()
    if state['head']!=remote_oid or state['branch']!=scope.local_branch or target_before(transaction,scope)!=before:raise PermissionError('Private clone state differs from exact scope')
    params={'identity_kind':'parent_workspace','repository':scope.repository,'target_before':before,
        'private_candidate':{'directory':str(candidate),'device':private.st_dev,'inode':private.st_ino},
        'remote_id':scope.remote_id,'remote_url':scope.remote_url,'remote_ref':scope.remote_ref,'remote_oid':remote_oid,
        'object_format':kind,'tracking_ref':'refs/remotes/'+scope.remote_id+'/'+scope.remote_ref.removeprefix('refs/heads/'),
        'local_branch':scope.local_branch,'pack_sha256':hashlib.sha256(pack).hexdigest(),'pack_size':len(pack),
        'policy_sha256':scope.policy_sha256}
    params['job_context']=job_context
    request=GitApprovalRequest.from_payload({'operation':'clone','workspace_id':scope.workspace_id,
        'repository_path':str(transaction.workspace),'repository_device':root.st_dev,'repository_inode':root.st_ino,
        'expected_head':None,'expected_tree':state['initial_tree'],'branch':scope.local_branch,'parameters':params})
    record={'version':1,'private_only':True,'canonical_published':False,'request':request.to_payload(),
        'request_sha256':request.digest,'private_state':state}
    (work/'prepared.json').write_text(json.dumps(record,sort_keys=True)+'\n');return request,candidate


class _CloneMount:
    """Materialization can enter only its verified, already-running job view."""
    wrap_argv=staticmethod(WorkspaceTransaction.wrap_argv)
    def __init__(self,transaction,fd):
        from agentporter.sandbox.workspace_git_runtime import runtime_launch_fds
        self.transaction,self.fd=transaction,fd
        self.launch_fds=(*transaction.launch_fds,fd,*runtime_launch_fds(transaction))
    @property
    def sandbox_workspace_fd(self):return self.transaction.inspection_fd
    def wrap_command(self,command):return list(command)
    def wrap_launcher(self,command):
        tail=command[command.index('--')+1:];prefix=WorkspaceTransaction.wrap_argv([])
        if tail[:len(prefix)]!=prefix:raise PermissionError('Expected fixed descriptor closer')
        argv=tail[len(prefix):]
        if len(argv)!=6 or argv[:5]!=['/usr/bin/python3','-I','-S','-c',_PROGRAM]:raise PermissionError('Only fixed offline clone program may enter live view')
        from agentporter.sandbox.workspace_git_runtime import fixed_runtime_command,FixedGitProgram
        return fixed_runtime_command(self.transaction,FixedGitProgram.CLONE,argv[5],pack_fd=self.fd)


def consume_clone(transaction,sandbox,scope,request,candidate,receipt,verifier,*,job_context,birth_authorization=None):
    """Consume exact authority then materialize within the existing private view.

    Does not publish; normal quiescent transaction finalization owns publication.
    Requires typed host authority and the exact admitted live job view before
    claiming a receipt. Offline or sibling-overlay materialization is unsupported.
    """
    if not isinstance(scope,CloneScope):raise PermissionError('Trusted clone scope required')
    from agentporter.git_clone_authority import CloneBirthAuthorization
    from agentporter.sandbox.workspace_git_runtime import runtime_launch_fds
    if not isinstance(birth_authorization,CloneBirthAuthorization) or birth_authorization.transaction is not transaction:
        raise PermissionError('Clone materialization requires its exact typed owner birth authority')
    runtime_launch_fds(transaction)
    document=birth_authorization.document
    if document.get('request_sha256')!=request.digest or document.get('request')!=request.to_payload():
        raise PermissionError('Clone birth authority differs from the exact request before claim')
    if (birth_authorization.backend.sandbox is not sandbox or transaction.git_sandbox is not sandbox
            or birth_authorization.backend._validate_job(request) is not transaction):
        raise PermissionError('Clone requires its exact admitted running worker transaction')
    params=request.to_payload()['parameters'];job_context=_job_context(transaction,job_context)
    before=target_before(transaction,scope);info=Path(candidate).stat();root=os.fstat(transaction._root_fd)
    expected={'identity_kind':'parent_workspace','repository':scope.repository,'target_before':before,
        'private_candidate':{'directory':str(candidate),'device':info.st_dev,'inode':info.st_ino},
        'remote_id':scope.remote_id,'remote_url':scope.remote_url,'remote_ref':scope.remote_ref,
        'local_branch':scope.local_branch,'policy_sha256':scope.policy_sha256,'job_context':job_context}
    payload=request.to_payload()
    if (payload['operation']!='clone' or payload['workspace_id']!=scope.workspace_id
        or (payload['repository_path'],payload['repository_device'],payload['repository_inode'])!=(str(transaction.workspace),root.st_dev,root.st_ino)
        or any(params.get(key)!=value for key,value in expected.items())):raise PermissionError('Clone request differs from exact host scope')
    source=Path(candidate).parent/'input.pack';fd=os.open(source,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        pack=os.read(fd,64*1024*1024+1)
        if len(pack)!=params['pack_size'] or hashlib.sha256(pack).hexdigest()!=params['pack_sha256']:raise PermissionError('Prepared clone pack changed')
        validate_pack(pack,params['object_format']);os.lseek(fd,0,os.SEEK_SET)
        verifier.verify_and_consume(receipt,request)
        if target_before(transaction,scope)!=before:raise PermissionError('Clone target changed after receipt consumption')
        approved=birth_authorization.validate()
        if approved!=params:raise PermissionError('Clone birth capability differs from consumed request')
        remote={key:params[key] for key in ('remote_id','remote_url','remote_ref','tracking_ref')}
        result=sandbox._run_command(workspace_path=str(transaction.workspace),
            argv=['/usr/bin/python3','-I','-S','-c',_PROGRAM,json.dumps({'object_format':params['object_format'],
             'remote_oid':params['remote_oid'],'branch':scope.local_branch,'repository':scope.repository,'pack_sha256':params['pack_sha256'],**remote})],
            writable=True,git_metadata_writable=True,network_access=False,workspace_transaction=_CloneMount(transaction,fd),
            require_resources=True,timeout_seconds=90,max_output_bytes=8192)
    finally:os.close(fd)
    if result['exit_code']:raise PermissionError('Consumed private clone materialization failed: '+result['stderr'][-500:])
    output=result['stdout']
    from agentporter.sandbox.workspace_git_runtime import parse_runtime_output
    _,output=parse_runtime_output(output)
    return json.loads(output)
