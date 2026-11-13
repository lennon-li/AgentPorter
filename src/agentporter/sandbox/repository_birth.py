"""Host-authorized publication of newly born conventional Git repositories.

The default workspace delta path still rejects every .git entry. This capability
is constructed only by a trusted transaction that separately opted into Git
birth, after its worker envelope is quiescent. It never authorizes replacement
of an existing Git directory or writes to an existing repository's metadata.
"""
from dataclasses import dataclass
import configparser
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import time

from agentporter.sandbox.workspace_delta import UnsafeWorkspaceDelta, _require_public_path, _workspace_parent
from agentporter.git_commits import _inspect_metadata, _mount_id
from agentporter.git_smart_http import _ref

_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
_OID = r'(?:[0-9a-f]{40}|[0-9a-f]{64})'
_ALLOWED_FILE = re.compile(r'(?:HEAD|config|description|index|COMMIT_EDITMSG|ORIG_HEAD|packed-refs|info/exclude|logs/HEAD|sharedindex\.'+_OID+r'|refs/(?:heads|tags)/[^\x00]+|refs/stash|logs/refs/(?:heads|tags)/[^\x00]+|logs/refs/stash|objects/[0-9a-f]{2}/[0-9a-f]{38}(?:[0-9a-f]{24})?|objects/pack/pack-'+_OID+r'\.(?:pack|idx|rev)|hooks/[^/]+\.sample)\Z')
_ALLOWED_DIR = re.compile(r'(?:objects(?:/(?:info|pack|[0-9a-f]{2}))?|refs(?:/(?:heads|tags)(?:/[^\x00]+)?)?|logs(?:/refs(?:/(?:heads|tags)(?:/[^\x00]+)?)?)?|hooks|branches|info)\Z')


def _canonical_dir_fd(transaction,relative):
    with _workspace_parent(transaction._root_path,relative+'/placeholder') as (parent,_):
        return os.dup(parent)


def _canonical_info(transaction,relative):
    with _workspace_parent(transaction._root_path,relative) as (parent,name):
        try:return os.stat(name,dir_fd=parent,follow_symlinks=False)
        except FileNotFoundError:return None


def _digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()).hexdigest()


def _config(data, clone=None):
    if len(data) > 8192 or b'\x00' in data:
        raise UnsafeWorkspaceDelta('New Git configuration exceeds its bounded schema')
    parser = configparser.ConfigParser(interpolation=None, strict=True)
    try: parser.read_string(data.decode('utf-8'))
    except (ValueError, configparser.Error, UnicodeError) as error:
        raise UnsafeWorkspaceDelta('Invalid new Git configuration') from error
    allowed = {'core': {'repositoryformatversion', 'filemode', 'bare', 'logallrefupdates',
                         'ignorecase', 'precomposeunicode', 'hookspath', 'fsmonitor'},
               'extensions': {'objectformat'}, 'user': {'name', 'email'}}
    if clone is not None:
        remote='remote "'+clone['remote_id']+'"';branch='branch "'+clone['local_branch'].removeprefix('refs/heads/')+'"'
        expected={remote:{'url':clone['remote_url'],'fetch':'+'+clone['remote_ref']+':'+clone['tracking_ref']},
                  branch:{'remote':clone['remote_id'],'merge':clone['remote_ref']}}
        for section,values in expected.items():
            if section not in parser or dict(parser[section])!=values:raise UnsafeWorkspaceDelta('Clone configuration differs from exact approved remote/ref')
            parser.remove_section(section)
    if parser.defaults() or any(s not in allowed or set(parser[s])-allowed[s] for s in parser.sections()):
        raise UnsafeWorkspaceDelta('New Git configuration selects an unapproved behavior')
    if 'core' not in parser or parser['core'].get('bare', '').lower() != 'false':
        raise UnsafeWorkspaceDelta('New repository must be a conventional worktree')
    core = parser['core']
    if core.get('repositoryformatversion') not in ('0', '1'):
        raise UnsafeWorkspaceDelta('Unsupported new repository format')
    if core.get('hookspath', '/dev/null') != '/dev/null' or core.get('fsmonitor', 'false').lower() not in ('false', '0'):
        raise UnsafeWorkspaceDelta('New Git configuration enables a command hook')
    for key in ('filemode', 'logallrefupdates', 'ignorecase', 'precomposeunicode'):
        if key in core and core[key].lower() not in ('true', 'false', '0', '1'):
            raise UnsafeWorkspaceDelta('Invalid new Git boolean')
    if 'extensions' in parser and (dict(parser['extensions']) != {'objectformat': 'sha256'} or core['repositoryformatversion'] != '1'):
        raise UnsafeWorkspaceDelta('Unsupported new Git extension')
    if core['repositoryformatversion'] == '1' and 'extensions' not in parser:
        raise UnsafeWorkspaceDelta('New SHA256 repository lacks its object format')
    for section in parser.sections():
        if any(any(ord(c) < 32 for c in value) for value in parser[section].values()):
            raise UnsafeWorkspaceDelta('Control characters in new Git configuration')


def _manifest(metadata, *, budget=None, deadline=None, clone=None):
    descriptor = os.open(metadata, _FLAGS)
    try:
        _inspect_metadata(descriptor, _mount_id(descriptor))
        extra_files=set() if clone is None else {clone['tracking_ref'],'logs/'+clone['tracking_ref']}
        extra_dirs={str(parent) for name in extra_files for parent in PurePosixPath(name).parents if str(parent)!='.'}
        result = {}
        budget = [100000, 256*1024*1024] if budget is None else budget
        deadline = time.monotonic()+60 if deadline is None else deadline
        def walk(fd, prefix='', depth=0):
            if depth > 64 or time.monotonic()>=deadline: raise UnsafeWorkspaceDelta('New Git metadata exceeds depth/time budget')
            before = os.fstat(fd)
            for entry in sorted(os.scandir(fd), key=lambda e: e.name):
                name = prefix + entry.name; info = entry.stat(follow_symlinks=False)
                if time.monotonic()>=deadline:raise UnsafeWorkspaceDelta('New Git metadata exceeds time budget')
                budget[0] -= 1
                if budget[0] < 0: raise UnsafeWorkspaceDelta('New Git metadata exceeds its entry budget')
                if info.st_mode & 0o7000: raise UnsafeWorkspaceDelta('Privileged new Git metadata mode')
                if stat.S_ISDIR(info.st_mode):
                    if not _ALLOWED_DIR.fullmatch(name) and name not in extra_dirs: raise UnsafeWorkspaceDelta('Unapproved new Git metadata directory')
                    child = os.open(entry.name, _FLAGS, dir_fd=fd)
                    try: result[name] = {'kind': 'directory', 'mode': stat.S_IMODE(info.st_mode)}; walk(child, name+'/', depth+1)
                    finally: os.close(child)
                elif stat.S_ISREG(info.st_mode) and info.st_nlink == 1:
                    if not _ALLOWED_FILE.fullmatch(name) and name not in extra_files: raise UnsafeWorkspaceDelta('Unapproved new Git metadata file')
                    child = os.open(entry.name, os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC, dir_fd=fd)
                    try:
                        first = os.fstat(child); data = bytearray()
                        if first.st_size > 64*1024*1024: raise UnsafeWorkspaceDelta('New Git metadata file too large')
                        while block := os.read(child, 65536):
                            if time.monotonic()>=deadline:raise UnsafeWorkspaceDelta('New Git metadata exceeds time budget')
                            data.extend(block); budget[1] -= len(block)
                            if budget[1] < 0 or len(data)>64*1024*1024: raise UnsafeWorkspaceDelta('New Git metadata exceeds byte budget')
                        last = os.fstat(child)
                        if (first.st_dev,first.st_ino,first.st_size,first.st_mtime_ns,first.st_ctime_ns)!=(last.st_dev,last.st_ino,last.st_size,last.st_mtime_ns,last.st_ctime_ns): raise UnsafeWorkspaceDelta('New Git metadata changed during inspection')
                        if name == 'config': _config(bytes(data),clone)
                        result[name] = {'kind':'file','mode':stat.S_IMODE(first.st_mode),'sha256':hashlib.sha256(data).hexdigest()}
                    finally: os.close(child)
                else: raise UnsafeWorkspaceDelta('New Git metadata contains aliases or special entries')
            after = os.fstat(fd)
            if (before.st_dev,before.st_ino,before.st_mtime_ns,before.st_ctime_ns)!=(after.st_dev,after.st_ino,after.st_mtime_ns,after.st_ctime_ns): raise UnsafeWorkspaceDelta('New Git directory changed during inspection')
        walk(descriptor)
        if not {'HEAD','config','objects','refs'} <= set(result): raise UnsafeWorkspaceDelta('Incomplete new Git metadata')
        return result
    finally: os.close(descriptor)


_INSPECT = r'''
import json, subprocess, sys
exec(sys.argv[1])
if any(not (name.startswith(('refs/heads/','refs/tags/')) or name=='refs/stash') for name in state['refs']):
 raise RuntimeError('New local repository contains protected refs')
for args in (['ls-files','-z','--',':(top,literal).venv'],
             ['log','--all','--reflog','--full-history','--format=%H','-z','--',':(top,literal).venv']):
 check = subprocess.run(base+args,env=environment,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=20)
 if check.returncode or check.stdout:raise RuntimeError('New Git metadata references excluded development files')
result = subprocess.run(base+['fsck','--strict','--no-reflogs'],env=environment,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=30)
if result.returncode or len(result.stdout)+len(result.stderr)>1048576: raise RuntimeError('New repository graph validation failed')
'''


@dataclass(frozen=True)
class _Birth:
    repository: str
    metadata_manifest_json: bytes
    state_json: bytes
    source_identity: tuple
    existing_identity: tuple | None = None
    existing_record_json: bytes | None = None
    clone_json: bytes | None = None

    def payload(self, parent=''):
        relative = str(PurePosixPath(self.repository).relative_to(PurePosixPath(parent))) if parent else self.repository
        return {'repository': relative, 'metadata_manifest': json.loads(self.metadata_manifest_json),
                'state': json.loads(self.state_json), **({'clone_authorization':json.loads(self.clone_json)} if self.clone_json is not None else {})}


class RepositoryBirths:
    def __init__(self, transaction, births):
        self._transaction = transaction; self._births = tuple(births)
        info = transaction.upper.stat(); self._upper_identity = (info.st_dev, info.st_ino)
        parent = os.fstat(transaction._root_fd); self._workspace_identity = (parent.st_dev, parent.st_ino)

    def validate(self, selected=None):
        tx = self._transaction; tx._check_root_identity()
        if not tx._allow_git_birth or not tx.writable: raise UnsafeWorkspaceDelta('Git birth is not host-authorized')
        info = tx.upper.stat()
        if (info.st_dev,info.st_ino) != self._upper_identity: raise UnsafeWorkspaceDelta('Git birth upper identity changed')
        selected=self._births if selected is None else selected
        for birth in selected:
            source = tx.upper/birth.repository; info = source.stat()
            if (info.st_dev,info.st_ino) != birth.source_identity: raise UnsafeWorkspaceDelta('Git birth source substituted')
            if birth.existing_identity is not None:
                from agentporter.sandbox.workspace_directories import _directory_record
                fd=_canonical_dir_fd(tx,birth.repository)
                try:
                    info=os.fstat(fd)
                    if ((info.st_dev,info.st_ino)!=birth.existing_identity
                            or _directory_record(fd,'.')!=json.loads(birth.existing_record_json)):
                        raise UnsafeWorkspaceDelta('Git birth existing target identity or access metadata changed')
                    with os.scandir(fd) as entries:
                        if next(entries,None) is not None:raise UnsafeWorkspaceDelta('Git birth existing target is no longer empty')
                finally:os.close(fd)
            clone=None
            if birth.clone_json is not None:
                capability=tx._approved_clone_births[birth.repository]
                clone=capability.validate()
                if capability.document_json!=birth.clone_json:raise UnsafeWorkspaceDelta('Clone birth authority changed')
            if _digest(_manifest(source/'.git',clone=clone)) != _digest(json.loads(birth.metadata_manifest_json)):
                raise UnsafeWorkspaceDelta('Git birth metadata changed after validation')
        return tuple(b.repository+'/.git' for b in selected)

    def replacement_paths(self):
        return tuple(b.repository for b in self._births if b.existing_identity is not None)

    def replacement_identity(self, source):
        relative=Path(source).relative_to(self._transaction.upper).as_posix()
        return next((b.existing_identity for b in self._births if b.repository==relative),None)

    def for_tree(self, source):
        prefix = Path(source).relative_to(self._transaction.upper).as_posix()
        selected=tuple(b for b in self._births if b.repository == prefix or b.repository.startswith(prefix+'/'))
        self.validate(selected)
        return [b.payload(prefix) for b in selected]


def validate_payloads(records):
    if not isinstance(records,list) or len(records)>128: raise UnsafeWorkspaceDelta('Invalid Git birth directory evidence')
    prefixes=[]
    for record in records:
        if not isinstance(record,dict) or set(record) not in ({'repository','metadata_manifest','state'},{'repository','metadata_manifest','state','clone_authorization'}): raise UnsafeWorkspaceDelta('Invalid Git birth record')
        relative=record['repository']
        if not isinstance(relative,str):raise UnsafeWorkspaceDelta('Invalid Git birth target')
        if relative != '.': _require_public_path(relative)
        if not isinstance(relative,str) or (relative!='.' and (str(PurePosixPath(relative))!=relative or relative.startswith('/') or '..'in PurePosixPath(relative).parts)):raise UnsafeWorkspaceDelta('Invalid Git birth target')
        clone=record.get('clone_authorization')
        extra_files=set();extra_dirs=set()
        if clone is not None:
            from agentporter.git_approvals import GitApprovalRequest
            req=GitApprovalRequest.from_payload(clone['request']);params=req.to_payload()['parameters']
            if req.to_payload()['operation']!='clone' or clone.get('request_sha256')!=req.digest:raise UnsafeWorkspaceDelta('Invalid clone birth evidence')
            tracking=params['tracking_ref']
            if tracking!='refs/remotes/'+params['remote_id']+'/'+params['remote_ref'].removeprefix('refs/heads/'):raise UnsafeWorkspaceDelta('Invalid exact clone tracking ref')
            extra_files={tracking,'logs/'+tracking};extra_dirs={str(p) for n in extra_files for p in PurePosixPath(n).parents if str(p)!='.'}
        manifest=record['metadata_manifest']
        if not isinstance(manifest,dict) or not {'HEAD','config','objects','refs'}<=set(manifest): raise UnsafeWorkspaceDelta('Invalid Git birth metadata manifest')
        for name,entry in manifest.items():
            if not isinstance(entry,dict) or entry.get('kind') not in ('file','directory'):raise UnsafeWorkspaceDelta('Invalid Git birth entry')
            if entry['kind']=='file':
                if set(entry)!={'kind','mode','sha256'} or not isinstance(name,str) or not (_ALLOWED_FILE.fullmatch(name) or name in extra_files) or not isinstance(entry['sha256'],str) or not re.fullmatch('[0-9a-f]{64}',entry['sha256']):raise UnsafeWorkspaceDelta('Invalid Git birth file')
            elif set(entry)!={'kind','mode'} or not isinstance(name,str) or not (_ALLOWED_DIR.fullmatch(name) or name in extra_dirs): raise UnsafeWorkspaceDelta('Invalid Git birth directory')
            if type(entry['mode'])is not int or entry['mode'] & ~0o777:raise UnsafeWorkspaceDelta('Invalid Git birth mode')
        state=record['state']
        if not isinstance(state,dict) or set(state)!={'head','branch','tree','refs','stash_log'}:raise UnsafeWorkspaceDelta('Invalid Git birth state')
        oid=lambda value:isinstance(value,str) and re.fullmatch(_OID,value) is not None and set(value)!={'0'}
        if (not oid(state['tree']) or state['head'] is not None and not oid(state['head'])
                or state['branch'] is not None and not _ref(state['branch'],branch=True)
                or not isinstance(state['refs'],dict) or len(state['refs'])>128 or not isinstance(state['stash_log'],str)):
            raise UnsafeWorkspaceDelta('Invalid Git birth logical state')
        width=len(state['tree'])
        if state['head'] is not None and len(state['head'])!=width:raise UnsafeWorkspaceDelta('Mixed Git birth object formats')
        for ref,value in state['refs'].items():
            if (not _ref(ref) or not (ref.startswith(('refs/heads/','refs/tags/')) or ref=='refs/stash' or ref in extra_files)
                    or not isinstance(value,dict) or set(value)!={'oid','symref'} or value['symref'] is not None
                    or not oid(value['oid']) or len(value['oid'])!=width):
                raise UnsafeWorkspaceDelta('Unapproved Git birth ref state')
        if clone is not None and state['refs'].get(params['tracking_ref'])!={'oid':params['remote_oid'],'symref':None}:raise UnsafeWorkspaceDelta('Clone tracking ref changed')
        prefix='.git' if relative=='.' else relative+'/.git'
        if prefix in prefixes:raise UnsafeWorkspaceDelta('Repeated Git birth target')
        prefixes.append(prefix)
    return tuple(prefixes)


def validate_tree_records(records, tree):
    """Bind copied bytes to the previously validated Git state, not new observations."""
    prefixes=validate_payloads(records)
    for record,prefix in zip(records,prefixes):
        if tree.get(prefix,{}).get('kind')!='directory':raise UnsafeWorkspaceDelta('Git birth metadata root is absent from directory proof')
        observed={name[len(prefix)+1:]:entry for name,entry in tree.items() if name.startswith(prefix+'/')}
        expected=record['metadata_manifest']
        if set(observed)!=set(expected):raise UnsafeWorkspaceDelta('Copied Git birth metadata namespace changed')
        for name,entry in expected.items():
            actual=observed[name]
            if any(actual.get(k)!=v for k,v in entry.items()):raise UnsafeWorkspaceDelta('Copied Git birth metadata differs from validated source')
    return prefixes


def discover(transaction):
    if not transaction._allow_git_birth: return None
    if transaction.git_sandbox is None: raise UnsafeWorkspaceDelta('Git birth requires supervised Git validation')
    births=[]; budget=100000
    metadata_budget=[100000,256*1024*1024];deadline=time.monotonic()+60
    for root,dirs,files in os.walk(transaction.upper,followlinks=False):
        for name in list(dirs)+files:
            budget-=1
            if budget<0 or time.monotonic()>=deadline:raise UnsafeWorkspaceDelta('Git birth scan exceeds entry/time budget')
            path=Path(root)/name;relative=path.relative_to(transaction.upper).as_posix()
            if name.lower()!='.git':
                _require_public_path(relative)
                continue
            if name in dirs:dirs.remove(name)
            if name!='.git' or not path.is_dir() or path.is_symlink():raise UnsafeWorkspaceDelta('Invalid new Git metadata target')
            repository=path.parent.relative_to(transaction.upper).as_posix()
            if repository=='.':raise UnsafeWorkspaceDelta('New workspace-root Git metadata requires explicit initialization support')
            # First primitive requires a wholly new enclosing subtree; existing
            # empty target support is handled separately, never silently adopted.
            pieces=PurePosixPath(repository).parts;new=False
            for count in range(1,len(pieces)+1):
                rel='/'.join(pieces[:count]);canonical_info=_canonical_info(transaction,rel)
                if canonical_info is not None and not stat.S_ISDIR(canonical_info.st_mode):raise UnsafeWorkspaceDelta('Git birth canonical parent is not an ordinary directory')
                if canonical_info is None:
                    if rel in transaction.baseline_directories:raise UnsafeWorkspaceDelta('Owner removed an original Git birth parent')
                    new=True;break
            existing_identity=None;existing_record=None
            if not new:
                from agentporter.sandbox.workspace_directories import _directory_record
                existing_record=transaction._birth_empty_directories.get(repository)
                if existing_record is None:raise UnsafeWorkspaceDelta('Git birth target must be new or an empty existing directory at job start')
                canonical=Path(transaction._root_path)/repository
                existing_fd=_canonical_dir_fd(transaction,repository)
                try:
                    with os.scandir(existing_fd) as entries:
                        if next(entries,None) is not None:raise UnsafeWorkspaceDelta('Git birth target must be new or an empty existing directory')
                    if _directory_record(existing_fd,'.')!=existing_record:raise UnsafeWorkspaceDelta('Original empty target changed since job start')
                    st=os.fstat(existing_fd);existing_identity=(st.st_dev,st.st_ino)
                finally:os.close(existing_fd)
            capability=getattr(transaction,'_approved_clone_births',{}).get(repository)
            clone=None
            if capability is not None:
                from agentporter.git_clone_authority import CloneBirthAuthorization
                if not isinstance(capability,CloneBirthAuthorization) or capability.transaction is not transaction:raise UnsafeWorkspaceDelta('Clone birth requires immutable host authority')
                clone=capability.validate()
            if clone is None:
                raise UnsafeWorkspaceDelta('Repository creation requires independent owner approval')
            manifest=_manifest(path,budget=metadata_budget,deadline=deadline,clone=clone)
            from agentporter.sandbox.workspace_git import _HISTORY_INSPECT
            remaining=deadline-time.monotonic()
            if remaining<=0:raise UnsafeWorkspaceDelta('Git birth validation exceeds time budget')
            result=transaction.git_sandbox._run_command(workspace_path=str(path.parent),
                argv=['/usr/bin/python3','-I','-S','-c',_INSPECT.replace("name=='refs/stash'","name=='refs/stash' or name=="+repr(clone['tracking_ref'])) if clone is not None else _INSPECT,_HISTORY_INSPECT],writable=False,
                network_access=False,timeout_seconds=max(1,min(60,int(remaining))),max_output_bytes=65536,require_resources=True)
            if result['exit_code']:raise UnsafeWorkspaceDelta('New repository Git graph validation failed: '+result['stderr'][-500:])
            state=json.loads(result['stdout'].splitlines()[0]);info=path.parent.stat()
            if time.monotonic()>=deadline:raise UnsafeWorkspaceDelta('Git birth validation exceeds time budget')
            if _manifest(path,deadline=deadline,clone=clone)!=manifest:raise UnsafeWorkspaceDelta('New Git metadata changed during graph validation')
            births.append(_Birth(repository,json.dumps(manifest,sort_keys=True).encode(),json.dumps(state,sort_keys=True).encode(),(info.st_dev,info.st_ino),existing_identity,None if existing_record is None else json.dumps(existing_record,sort_keys=True).encode(),None if capability is None else capability.document_json))
    if len(births)>128:raise UnsafeWorkspaceDelta('Too many new repositories')
    return RepositoryBirths(transaction,births) if births else None
