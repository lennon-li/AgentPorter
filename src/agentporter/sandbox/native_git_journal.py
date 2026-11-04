"""Stdlib-only instrumentation executed inside the trusted native importer."""

JOURNAL_PROGRAM = r'''
import base64, ctypes, hashlib, json, os, secrets, stat, sys
_journal_path = sys.argv[3] if len(sys.argv)>3 else None
_journal_sequence = 0
_journal_previous = None
_journal_bindings = {}
_publication_conflict = False
_journal_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC

def _journal_digest(data):
    return hashlib.sha256(json.dumps(data,sort_keys=True,separators=(',',':')).encode()).hexdigest()

def _journal_private(fd):
    info=os.fstat(fd)
    if not stat.S_ISDIR(info.st_mode) or info.st_uid!=os.getuid() or info.st_mode&0o077:
        raise RuntimeError('Native Git journal storage is not private')

def publication_bind_fd(target,descriptor,source):
    global _publication_conflict
    if _journal_path is None:return
    # Follow only the kernel-owned descriptor capability, never a mutable
    # source pathname. make_guard returns write-only descriptors.
    fd=os.open('/proc/self/fd/'+str(descriptor),os.O_RDONLY|os.O_NONBLOCK|os.O_CLOEXEC)
    try:
        before=os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink!=1 or before.st_size>67108864:
            raise RuntimeError('Unsupported native bound inode')
        def signature(info):return [info.st_dev,info.st_ino,info.st_mode,info.st_nlink,info.st_size,info.st_mtime_ns,info.st_ctime_ns]
        data=bytearray()
        while True:
            chunk=os.read(fd,65536)
            if not chunk:break
            data.extend(chunk)
            if len(data)>67108864:raise RuntimeError('Native bound inode exceeds size limit')
        attrs={key:base64.b64encode(os.getxattr(fd,key)).decode('ascii') for key in os.listxattr(fd)}
        if signature(before)!=signature(os.fstat(fd)):raise RuntimeError('Native bound inode changed during inspection')
        record={'signature':signature(before),'sha256':hashlib.sha256(data).hexdigest(),
            'uid':before.st_uid,'gid':before.st_gid,'xattrs':attrs}
        previous=_journal_bindings.get(target)
        if previous is not None:
            original=previous['record']
            if (original['signature'][:-1]!=record['signature'][:-1]
                    or any(original[key]!=record[key] for key in ('sha256','uid','gid','xattrs'))):
                _publication_conflict=True
                raise RuntimeError('Native descriptor rebinding differs from original owned inode')
        _journal_bindings[target]={'source':source,'record':record}
    finally:os.close(fd)

_native_channels = None
_native_ref_descriptors = []
_native_receiver_error = []
_native_before = {}
_native_expected = {}
_native_initial = {}


def publication_ref_begin(environment):
    global _native_channels, _native_before
    if _journal_path is None:return environment, ()
    import array, socket, threading
    with open('/native-git-provenance.so','rb') as bridge:
        if hashlib.sha256(bridge.read(4194305)).hexdigest()!=json.loads(sys.argv[1])['native_bridge']['library_sha256']:
            raise RuntimeError('Mounted native Git bridge differs from bound plan')
    with open(_journal_path+'/native-before.json') as saved:_native_before=json.load(saved)
    parent, child=socket.socketpair(socket.AF_UNIX,socket.SOCK_SEQPACKET)
    _native_channels=(parent,child)
    def receive():
        while True:
            descriptors=[]
            try:
                packet,control,flags,_=parent.recvmsg(8192,socket.CMSG_SPACE(4),socket.MSG_CMSG_CLOEXEC)
                if not packet:break
                for level,kind,value in control:
                    if level!=socket.SOL_SOCKET or kind!=socket.SCM_RIGHTS:raise RuntimeError('Unexpected native descriptor control')
                    values=array.array('i');values.frombytes(value);descriptors.extend(values)
                if flags&(socket.MSG_TRUNC|socket.MSG_CTRUNC) or len(descriptors)!=1:
                    raise RuntimeError('Truncated native descriptor capability')
                descriptor=descriptors[0]
                phase,opened,relative=packet.decode('utf-8').split(':',2);opened=int(opened)
                if phase not in {'o','c'}:raise RuntimeError('Invalid native descriptor phase')
                if (any(part in {'','.','..'} for part in relative.split('/'))
                        or len(_native_ref_descriptors)>=512):raise RuntimeError('Invalid native descriptor namespace')
                info=os.fstat(descriptor)
                if not stat.S_ISREG(info.st_mode) or info.st_nlink!=1:raise RuntimeError('Invalid native descriptor inode')
                created=(opened&(os.O_CREAT|os.O_EXCL))==(os.O_CREAT|os.O_EXCL)
                lock=relative.endswith('.lock') and relative.startswith('refs/')
                log=relative.startswith('logs/refs/')
                trusted=created and (lock or log)
                if log and relative in _native_before and phase=='o':
                    expected=_native_before[relative]
                    actual=[info.st_dev,info.st_ino,info.st_mode,info.st_nlink,info.st_size,info.st_mtime_ns,info.st_ctime_ns]
                    trusted=actual[:-1]==expected['signature'][:-1] and actual[-1]>=expected['signature'][-1]
                    if not trusted:raise RuntimeError('Native reflog opened a later owner inode')
                if phase=='c':
                    previous=next((entry for entry in _native_ref_descriptors
                        if entry[0]==relative and os.fstat(entry[1]).st_ino==info.st_ino
                        and os.fstat(entry[1]).st_dev==info.st_dev),None)
                    if previous is None:raise RuntimeError('Native close lacks retained open capability')
                    trusted=previous[2]
                    if trusted:
                        os.fsync(descriptor)
                        publication_ref_receipt(relative,descriptor)
                else:
                    if trusted:
                        publication_bind_fd('__initial__/'+relative,descriptor,relative)
                        _native_initial[relative]=_journal_bindings.pop('__initial__/'+relative)['record']
                        if log and relative in _native_before:
                            expected=_native_before[relative]
                            if any(_native_initial[relative][key]!=expected[key] for key in ('sha256','uid','gid','xattrs')):
                                raise RuntimeError('Native opened reflog bytes/access metadata differ from protected before copy')
                    if trusted and log:publication_ref_opened(relative,descriptor)
                    _native_ref_descriptors.append((relative,descriptor,trusted))
                if phase=='c':os.close(descriptor)
                descriptors=[]
                parent.send(b'1')
            except BaseException as error:
                _native_receiver_error.append(str(error))
                for descriptor in descriptors:os.close(descriptor)
                try:parent.send(b'0')
                except OSError:pass
                break
    receiver=threading.Thread(target=receive,daemon=True);receiver.start()
    _native_channels=(parent,child,receiver)
    return dict(environment,LD_PRELOAD='/native-git-provenance.so',
                AGENTPORTER_NATIVE_SOCKET=str(child.fileno())), (child.fileno(),)


def publication_ref_opened(relative,descriptor):
    target=relative[5:]
    native_plan=json.loads(sys.argv[1]);old=native_plan['before']['refs'].get(target);new=native_plan['after']['refs'].get(target)
    if new is None:raise RuntimeError('Unexpected reflog append for deleted native ref')
    publication_bind_fd('__opened__/'+relative,descriptor,relative)
    record=_journal_bindings.pop('__opened__/'+relative)['record']
    copy=os.open('/proc/self/fd/'+str(descriptor),os.O_RDONLY|os.O_CLOEXEC)
    try:
        data=bytearray()
        while True:
            part=os.read(copy,65536)
            if not part:break
            data.extend(part)
            if len(data)>67108864:raise RuntimeError('Native opened reflog exceeds limit')
    finally:os.close(copy)
    if hashlib.sha256(data).hexdigest()!=record['sha256']:raise RuntimeError('Native opened reflog changed')
    old_oid=old['oid'] if old else '0'*len(new['oid'])
    line=(old_oid+' '+new['oid']+' AgentPorter <agents@agentporter.invalid> '+
          str(native_plan.get('publication_time',0))+' +0000\tAgentPorter local Git publication\n').encode()
    expected=bytes(data)+line
    _native_expected[relative]=hashlib.sha256(expected).hexdigest()
    parent=os.open(_journal_path,_journal_flags)
    blobs=os.open('blobs',_journal_flags,dir_fd=parent)
    try:
        try:_journal_write(blobs,_native_expected[relative],expected)
        except FileExistsError:pass
        os.fsync(blobs)
        with os.scandir(parent) as entries:count=sum(entry.name.startswith('opened-') for entry in entries)
        if count>=512:raise RuntimeError('Native opened receipt count exceeds limit')
        git=os.open('/workspace/.git',_journal_flags)
        try:identity=[os.fstat(git).st_dev,os.fstat(git).st_ino]
        finally:os.close(git)
        receipt={'schema':1,'sequence':count,'plan_sha256':_journal_digest(native_plan),'git':identity,
            'target':relative,'before':record,'after_sha256':_native_expected[relative],'after_size':len(expected)}
        _journal_write(parent,'opened-%08d.json'%count,json.dumps(receipt,sort_keys=True,separators=(',',':')).encode())
    finally:os.close(blobs);os.close(parent)


def publication_ref_receipt(relative,descriptor):
    target=relative[:-5] if relative.endswith('.lock') else relative
    publication_bind_fd(target,descriptor,relative)
    binding=_journal_bindings[target]
    if relative.endswith('.lock'):
        planned=json.loads(sys.argv[1]);old=planned['before']['refs'].get(target);new=planned['after']['refs'].get(target)
        if old!=new and old is not None and new is not None and old.get('symref') is not None:
            approval=planned.get('approved_pull')
            if approval is None:raise RuntimeError('Symbolic verification lacks exact pull authority')
            parameters=approval['authorization']['request']['parameters']
            if (old['symref']!=parameters['tracking_ref'] or new['symref']!=old['symref']
                    or old['oid']!=parameters['old_oid'] or new['oid']!=parameters['new_oid']
                    or target==parameters['tracking_ref']):
                raise RuntimeError('Symbolic verification differs from exact signed transition')
            # update-ref verifies this symbolic ref without writing its bytes.
            # Native metadata validation still requires its exact before inode.
            expected=b''
        else:
            expected=((new['oid']+'\n').encode() if new is not None and old!=new else b'')
        known=hashlib.sha256(expected).hexdigest()
    else:known=_native_expected.get(relative)
    initial=_native_initial.get(relative);actual=binding['record']
    if (known is None or actual['sha256']!=known or initial is None
            or actual['signature'][:4]!=initial['signature'][:4]
            or any(actual[key]!=initial[key] for key in ('uid','gid','xattrs'))):
        _journal_bindings.pop(target,None)
        raise RuntimeError('Native descriptor bytes differ from the exact authorized mutation')
    parent=os.open(_journal_path,_journal_flags)
    try:
        git=os.open('/workspace/.git',_journal_flags)
        try:identity=[os.fstat(git).st_dev,os.fstat(git).st_ino]
        finally:os.close(git)
        with os.scandir(parent) as entries:count=sum(entry.name.startswith('descriptor-') for entry in entries)
        if count>=512:raise RuntimeError('Native descriptor receipt limit exceeded')
        blobs=os.open('blobs',_journal_flags,dir_fd=parent)
        copy=os.open('/proc/self/fd/'+str(descriptor),os.O_RDONLY|os.O_CLOEXEC)
        try:
            data=bytearray()
            while True:
                part=os.read(copy,65536)
                if not part:break
                data.extend(part)
                if len(data)>67108864:raise RuntimeError('Native receipt blob exceeds limit')
            if hashlib.sha256(data).hexdigest()!=binding['record']['sha256']:
                raise RuntimeError('Native receipt descriptor changed')
            try:_journal_write(blobs,binding['record']['sha256'],data)
            except FileExistsError:pass
            os.fsync(blobs)
        finally:os.close(copy);os.close(blobs)
        receipt={'schema':1,'sequence':count,'plan_sha256':_journal_digest(json.loads(sys.argv[1])),
                 'git':identity,'target':target,'binding':binding}
        _journal_write(parent,'descriptor-%08d.json'%count,
            json.dumps(receipt,sort_keys=True,separators=(',',':')).encode())
    finally:os.close(parent)


def publication_ref_snapshot(stage):
    if _journal_path is None:return
    if _native_receiver_error:raise RuntimeError('Native descriptor receiver failed: '+_native_receiver_error[0])
    if stage=='refs_prepared':
        native_plan=json.loads(sys.argv[1]);before=native_plan['before']['refs'];after=native_plan['after']['refs']
        for target in set(before)|set(after):
            if before.get(target)!=after.get(target):
                if not any(relative==target+'.lock' and trusted for relative,_,trusted in _native_ref_descriptors):
                    raise RuntimeError('Changed native ref lacks actual created lock capability')
    # Every message is acknowledged only after retaining the actual FD. Git's
    # prepare/commit stdout acknowledgement occurs after those opens return.
    for relative,descriptor,trusted in list(_native_ref_descriptors):
        if not trusted:continue
        info=os.fstat(descriptor)
        if info.st_nlink==0:continue
        if relative.endswith('.lock'):
            publication_bind_fd(relative,descriptor,relative)
            publication_bind_fd(relative[:-5],descriptor,relative)
        elif stage=='refs_committed':
            publication_bind_fd(relative,descriptor,relative)


def publication_index_path(name):
    if _journal_path is None:return '/workspace/.git/'+name
    parent=os.open(_journal_path,_journal_flags)
    try:
        _journal_private(parent)
        try:os.mkdir('index-work',0o700,dir_fd=parent)
        except FileExistsError:pass
        child=os.open('index-work',_journal_flags,dir_fd=parent)
        try:_journal_private(child);os.fsync(child)
        finally:os.close(child)
        os.fsync(parent)
    finally:os.close(parent)
    return _journal_path+'/index-work/'+name

def publication_install_index(name,parent,path):
    global _publication_conflict
    if _journal_path is None:return
    source=None;output=None
    try:
        source=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
        before=os.fstat(source)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink!=1 or before.st_size>67108864:
            raise RuntimeError('Unsupported privately staged Git index')
        output=os.open('.',os.O_RDWR|os.O_TMPFILE|os.O_CLOEXEC,0o600,dir_fd=parent)
        with os.fdopen(os.dup(output),'wb') as stream:
            count=0
            while True:
                data=os.read(source,65536)
                if not data:break
                count+=len(data)
                if count>67108864:raise RuntimeError('Privately staged Git index exceeds limit')
                stream.write(data)
            stream.flush()
        after=os.fstat(source)
        if (before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns,before.st_ctime_ns)!=(after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns):
            raise RuntimeError('Private Git index changed during staging')
        os.fchmod(output,stat.S_IMODE(before.st_mode));os.fsync(output)
        libc=ctypes.CDLL(None,use_errno=True);link=libc.linkat
        link.argtypes=[ctypes.c_int,ctypes.c_char_p,ctypes.c_int,ctypes.c_char_p,ctypes.c_int];link.restype=ctypes.c_int
        if link(-100,os.fsencode('/proc/self/fd/'+str(output)),parent,os.fsencode(name),0x400):
            error=ctypes.get_errno();raise OSError(error,os.strerror(error),name)
        os.fsync(parent)
        publication_bind_fd(name,output,name)
        publication_bind_fd('index',output,name)
    except BaseException:
        _publication_conflict=True
        raise
    finally:
        for descriptor in (output,source):
            if descriptor is not None:os.close(descriptor)

def _journal_write(parent,name,data):
    fd=os.open('.',os.O_RDWR|os.O_TMPFILE|os.O_CLOEXEC,0o600,dir_fd=parent)
    try:
        with os.fdopen(os.dup(fd),'wb') as stream:stream.write(data);stream.flush()
        os.fsync(fd)
        libc=ctypes.CDLL(None,use_errno=True)
        link=libc.linkat
        link.argtypes=[ctypes.c_int,ctypes.c_char_p,ctypes.c_int,ctypes.c_char_p,ctypes.c_int]
        link.restype=ctypes.c_int
        if link(-100,os.fsencode('/proc/self/fd/'+str(fd)),parent,os.fsencode(name),0x400):
            error=ctypes.get_errno();raise OSError(error,os.strerror(error),name)
        os.fsync(parent)
    finally:
        os.close(fd)

def publication_event(stage):
    global _journal_sequence,_journal_previous,_publication_conflict
    if _journal_path is None:return
    if stage in {'refs_prepared','refs_committed'}:publication_ref_snapshot(stage)
    journal=os.open(_journal_path,_journal_flags)
    blobs=None;root=None
    try:
        _journal_private(journal)
        if _journal_sequence==0:
            with os.scandir(journal) as entries:
                if any(entry.name.startswith('event-') for entry in entries):
                    raise RuntimeError('Native Git journal already has mutation evidence')
        try:os.mkdir('blobs',0o700,dir_fd=journal)
        except FileExistsError:pass
        blobs=os.open('blobs',_journal_flags,dir_fd=journal);_journal_private(blobs)
        root=os.open('/workspace/.git',_journal_flags)
        files={};directories={};budget=[100000,268435456]
        def walk(fd,prefix,depth):
            if depth>64:raise RuntimeError('Native Git journal depth exceeded')
            initial=os.fstat(fd)
            with os.scandir(fd) as entries:names=sorted(entry.name for entry in entries)
            for name in names:
                # config is a sealed anonymous sandbox mount, not the host's
                # canonical config inode. The host baseline binds that file.
                if prefix=='' and name in {'objects','config'}:continue
                budget[0]-=1
                if budget[0]<0:raise RuntimeError('Native Git journal entry limit exceeded')
                relative=prefix+name
                info=os.stat(name,dir_fd=fd,follow_symlinks=False)
                if stat.S_ISDIR(info.st_mode):
                    child=os.open(name,_journal_flags,dir_fd=fd)
                    try:
                        actual=os.fstat(child)
                        directories[relative]=[actual.st_dev,actual.st_ino]
                        walk(child,relative+'/',depth+1)
                    finally:os.close(child)
                elif stat.S_ISREG(info.st_mode):
                    child=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,dir_fd=fd)
                    try:
                        before=os.fstat(child)
                        if not stat.S_ISREG(before.st_mode) or before.st_nlink!=1 or before.st_size>67108864:
                            raise RuntimeError('Native Git journal unsupported file')
                        content=bytearray()
                        while True:
                            chunk=os.read(child,65536)
                            if not chunk:break
                            content.extend(chunk);budget[1]-=len(chunk)
                            if len(content)>67108864 or budget[1]<0:
                                raise RuntimeError('Native Git journal byte limit exceeded')
                        def signature(value):
                            return [value.st_dev,value.st_ino,value.st_mode,value.st_nlink,value.st_size,value.st_mtime_ns,value.st_ctime_ns]
                        attrs={key:base64.b64encode(os.getxattr(child,key)).decode('ascii') for key in os.listxattr(child)}
                        if signature(before)!=signature(os.fstat(child)):
                            raise RuntimeError('Native Git journal file changed during capture')
                        digest=hashlib.sha256(content).hexdigest()
                        files[relative]={'signature':signature(before),'sha256':digest,
                            'uid':before.st_uid,'gid':before.st_gid,'xattrs':attrs}
                        try:_journal_write(blobs,digest,content)
                        except FileExistsError:
                            existing=os.open(digest,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,dir_fd=blobs)
                            try:
                                original=os.fstat(existing)
                                if not stat.S_ISREG(original.st_mode) or original.st_nlink!=1 or original.st_size!=len(content):
                                    raise RuntimeError('Native Git journal blob identity invalid')
                                digest_check=hashlib.sha256()
                                while True:
                                    data=os.read(existing,65536)
                                    if not data:break
                                    digest_check.update(data)
                                if digest_check.hexdigest()!=digest:raise RuntimeError('Native Git journal blob changed')
                            finally:os.close(existing)
                    finally:os.close(child)
                else:raise RuntimeError('Native Git journal rejects aliases and special files')
            final=os.fstat(fd)
            if (initial.st_dev,initial.st_ino,initial.st_mtime_ns,initial.st_ctime_ns)!=(final.st_dev,final.st_ino,final.st_mtime_ns,final.st_ctime_ns):
                raise RuntimeError('Native Git journal directory changed during capture')
        walk(root,'',0)
        event={'schema':2,'sequence':_journal_sequence,'previous':_journal_previous,
            'stage':stage,'plan_sha256':_journal_digest(json.loads(sys.argv[1])),
            'git':[os.fstat(root).st_dev,os.fstat(root).st_ino],
            'files':files,'directories':directories,'bindings':dict(_journal_bindings)}
        encoded=json.dumps(event,sort_keys=True,separators=(',',':')).encode()
        if len(encoded)>1048576:raise RuntimeError('Native Git journal event limit exceeded')
        os.fsync(blobs)
        _journal_write(journal,'event-%08d.json'%_journal_sequence,encoded)
        _journal_previous=hashlib.sha256(encoded).hexdigest();_journal_sequence+=1
        if stage=='refs_commit_intent':
            for target,binding in _journal_bindings.items():
                if target.startswith('refs/') and binding['source']==target+'.lock':
                    if files.get(binding['source'])!=binding['record']:
                        _publication_conflict=True
                        raise RuntimeError('Native prepared ref lock differs from actual created capability')
        target={'index_publish_intent':'index','head_publish_intent':'HEAD',
                'stash_publish_intent':'logs/refs/stash'}.get(stage)
        if target is not None:
            binding=_journal_bindings.get(target)
            if binding is None or files.get(binding['source'])!=binding['record']:
                _publication_conflict=True
                raise RuntimeError('Native staged namespace differs from bound descriptor; preserve custody')
    finally:
        for descriptor in (root,blobs,journal):
            if descriptor is not None:os.close(descriptor)

def publication_cleanup_allowed():
    # Journal-enabled imports leave namespace cleanup to the host's protected
    # same-mount custody adapter. Direct offline fixtures keep native behavior.
    return _journal_path is None and not _publication_conflict
'''


def instrument(program):
    changes={
        "    transaction = subprocess.Popen(base + ['update-ref'":"    ref_environment, native_pass_fds = publication_ref_begin(ref_environment)\n    transaction = subprocess.Popen(base + ['update-ref'",
        "        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)":"        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, pass_fds=native_pass_fds)",
        "    index_environment = dict(env, GIT_INDEX_FILE=git_root + '/' + staged_index)":"    index_environment = dict(env, GIT_INDEX_FILE=publication_index_path(staged_index))",
        "    os.fsync(fd)\n    return fd":"    os.fsync(fd)\n    publication_bind_fd(os.path.relpath(os.readlink('/proc/self/fd/'+str(parent))+'/'+name,git_root),fd,os.path.relpath(os.readlink('/proc/self/fd/'+str(parent))+'/'+name,git_root))\n    return fd",
        "    for name in ('index.lock', 'HEAD.lock'):":"    publication_event('before_locks')\n    for name in ('index.lock', 'HEAD.lock'):",
        "        guards[name] = make_guard(name)":"        guards[name] = make_guard(name)\n        publication_event('guard_created')",
        "    # A trusted temporary per-worktree HEAD":"    publication_install_index(staged_index,root_fd,index_environment['GIT_INDEX_FILE'])\n    publication_event('index_staged')\n    # A trusted temporary per-worktree HEAD",
        "    transaction_step('prepare', 'prepare')":"    publication_event('refs_prepare_intent')\n    transaction_step('prepare', 'prepare')\n    publication_event('refs_prepared')",
        "    transaction_step('commit', 'commit')":"    publication_event('refs_commit_intent')\n    transaction_step('commit', 'commit')",
        "    transaction = None\n\n    if before['stash_log']":"    transaction = None\n    publication_event('refs_committed')\n\n    if before['stash_log']",
        "        stash_lock_fd = make_guard('stash.lock', stash_ref_fd)":"        _journal_bindings.pop('refs/stash.lock',None)\n        stash_lock_fd = make_guard('stash.lock', stash_ref_fd)\n        publication_event('stash_guard_created')",
        "                    os.replace(stash_temporary, 'stash'":"                    publication_event('stash_publish_intent')\n                    os.replace(stash_temporary, 'stash'",
        "                        os.unlink('stash', dir_fd=refs)":"                        publication_event('stash_delete_intent')\n                        os.unlink('stash', dir_fd=refs)",
        "                os.fsync(refs)":"                os.fsync(refs)\n                publication_event('stash_published')",
        "    os.replace(staged_index, 'index'":"    publication_event('index_publish_intent')\n    os.replace(staged_index, 'index'",
        "        os.fsync(index_fd)":"        os.fsync(index_fd)\n        publication_bind_fd('index',index_fd,staged_index)",
        "        os.fsync(head_fd)":"        os.fsync(head_fd)\n        publication_bind_fd('HEAD',head_fd,head_temporary)",
        "                        os.fsync(fd)\n                    finally:":"                        os.fsync(fd)\n                        _journal_bindings.pop('logs/refs/stash',None)\n                        publication_bind_fd('logs/refs/stash',fd,'logs/refs/'+stash_temporary)\n                    finally:",
        "    staged_index = None\n    head_value":"    staged_index = None\n    os.fsync(root_fd)\n    publication_event('index_published')\n    head_value",
        "    os.replace(head_temporary, 'HEAD'":"    publication_event('head_publish_intent')\n    os.replace(head_temporary, 'HEAD'",
        "    if current_state() != after:":"    publication_event('head_published')\n    if current_state() != after:",
        "finally:\n    if transaction is not None:":"finally:\n    publication_event('cleanup_intent')\n    if transaction is not None:",
        "    os.close(root_fd)\n# Persist metadata":"    os.close(root_fd)\n    publication_event('cleanup_finished')\n# Persist metadata",
        "                    os.unlink(stash_temporary, dir_fd=refs)":"                    if publication_cleanup_allowed():os.unlink(stash_temporary, dir_fd=refs)",
        "        os.unlink('stash.lock', dir_fd=stash_ref_fd)":"        if publication_cleanup_allowed():os.unlink('stash.lock', dir_fd=stash_ref_fd)",
        "            os.unlink(staged_index, dir_fd=root_fd)":"            if publication_cleanup_allowed():os.unlink(staged_index, dir_fd=root_fd)",
        "        os.unlink(name, dir_fd=root_fd)":"        if publication_cleanup_allowed():os.unlink(name, dir_fd=root_fd)",
    }
    for before,after in changes.items():
        if program.count(before)!=1:raise RuntimeError('Native Git journal injection marker mismatch: '+before)
        program=program.replace(before,after)
    result=JOURNAL_PROGRAM+'\n'+program
    compile(result,'<journaled-native-git>','exec')
    return result
