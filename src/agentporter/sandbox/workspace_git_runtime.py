"""Closed, host-only fixed Git programs in one verified live job view.

No worker or public API may select a program, namespace, PID, or source FD.
Only the two release-owned operation programs below can be dispatched.
"""
from enum import Enum
import fcntl
import json
import os
import stat

class FixedGitProgram(Enum):
    PULL='pull'
    CLONE='clone'

_RUNTIME_TEMPLATE = r'''
import ctypes,errno,json,os,select,signal,sys
libc=ctypes.CDLL(None,use_errno=True)
def checked(result,label):
 if result<0:raise OSError(ctypes.get_errno(),label)
 return result
user,mount,root=map(int,sys.argv[1:4]);request=sys.argv[4];supervisor=int(sys.argv[5])
def arm_supervisor():
 if os.getppid()!=supervisor:os._exit(125)
 checked(libc.prctl(1,signal.SIGKILL,0,0,0),'supervisor parent death signal')
 if os.getppid()!=supervisor:os._exit(125)
arm_supervisor()
checked(libc.setns(user,0x10000000),'setns user')
arm_supervisor()
checked(libc.setns(mount,0x20000),'setns mount')
arm_supervisor()
os.fchdir(root);os.chroot('.');os.chdir('/')
checked(libc.unshare(0x20000|0x40000000|0x20000000|0x08000000|0x04000000),'unshare helper namespaces')
checked(libc.mount(None,b'/',None,0x4000|0x40000,None),'private helper mounts')
for fd in (user,mount,root):os.close(fd)
parent_handle=os.pidfd_open(os.getpid(),0)
child=os.fork()
if child:
 os.close(parent_handle)
 def forward(number,frame):
  try:os.kill(child,number)
  except ProcessLookupError:pass
 for number in (signal.SIGTERM,signal.SIGINT,signal.SIGHUP):signal.signal(number,forward)
 _,status=os.waitpid(child,0)
 sys.exit(os.waitstatus_to_exitcode(status))
checked(libc.prctl(1,signal.SIGKILL,0,0,0),'helper parent death signal')
parent_poll=select.poll();parent_poll.register(parent_handle,select.POLLIN)
if parent_poll.poll(0):os._exit(125)
os.close(parent_handle)
checked(libc.mount(b'proc',b'/proc',b'proc',2|4|8,None),'fresh helper proc')
checked(libc.mount(b'tmpfs',b'/tmp',b'tmpfs',2|4,b'size=268435456,mode=1777'),'fresh helper tmp')
for capability in range(64):
 result=libc.prctl(24,capability,0,0,0)
 if result<0 and ctypes.get_errno()!=errno.EINVAL:checked(result,'drop capability bounding set')
checked(libc.prctl(47,4,0,0,0),'clear ambient capabilities')
class Header(ctypes.Structure):_fields_=[('version',ctypes.c_uint32),('pid',ctypes.c_int)]
class Data(ctypes.Structure):_fields_=[('effective',ctypes.c_uint32),('permitted',ctypes.c_uint32),('inheritable',ctypes.c_uint32)]
header=Header(0x20080522,0);data=(Data*2)()
checked(libc.capset(ctypes.byref(header),ctypes.byref(data)),'clear capabilities')
checked(libc.prctl(38,1,0,0,0),'no new privileges')
_PACK_STAGE_
for entry in os.listdir('/proc/self/fd'):
 fd=int(entry)
 if fd>2:
  try:os.close(fd)
  except OSError:pass
proof={}
for line in open('/proc/self/status'):
 key,_,value=line.partition(':')
 if key in ('CapEff','CapPrm','CapInh','CapBnd','CapAmb','NoNewPrivs'):proof[key]=value.strip()
proof.update(worker_tmp_visible=os.path.exists('/tmp/agentporter-worker-view-test'),host_home_visible=os.path.exists(_HOST_HOME_),net_devices=[line.split(':',1)[0].strip() for line in open('/proc/net/dev').read().splitlines()[2:]],pid=os.getpid(),uid=os.getuid(),namespaces={name:os.readlink('/proc/self/ns/'+name) for name in ('user','mnt','net','pid','ipc','uts')})
os.write(1,('AP_RUNTIME_PROOF '+json.dumps(proof,sort_keys=True)+'\n').encode())
os.execve('/usr/bin/python3',['/usr/bin/python3','-I','-S','-c',_FIXED_PROGRAM_,request],{'PATH':'/usr/bin:/bin','LANG':'C','LC_ALL':'C','HOME':'/nonexistent'})
'''

_CLONE_PACK_STAGE = r"""
import hashlib
pack=int(sys.argv[6]);digest=hashlib.sha256();total=0
with open('/tmp/incoming.pack','xb') as output:
 while block:=os.read(pack,65536):
  total+=len(block)
  if total>64*1024*1024:raise RuntimeError('Clone pack exceeds fixed bound')
  digest.update(block);output.write(block)
os.close(pack)
if digest.hexdigest()!=json.loads(request)['pack_sha256']:raise RuntimeError('Clone pack differs from exact request')
"""

def runtime_script(kind):
    if kind is FixedGitProgram.PULL:
        from agentporter.git_pull_integration import _PROGRAM
        program=_PROGRAM;pack_stage=''
    elif kind is FixedGitProgram.CLONE:
        from agentporter.git_clones import _CLONE_PROGRAM
        program=_CLONE_PROGRAM;pack_stage=_CLONE_PACK_STAGE
    else:raise PermissionError('Unknown fixed Git operation')
    return (_RUNTIME_TEMPLATE.replace('_PACK_STAGE_',pack_stage)
            .replace('_FIXED_PROGRAM_',repr(program))
            .replace('_HOST_HOME_',repr(os.path.expanduser('~'))))


def runtime_launch_fds(transaction):
    from agentporter.sandbox.workspace_transactions import WorkspaceTransaction
    if (not isinstance(transaction,WorkspaceTransaction) or transaction._closed or transaction._applied
            or not transaction.writable or transaction._runtime_view_fd is None
            or transaction._runtime_namespace_fds is None):
        raise PermissionError('Fixed Git helper requires its verified live transaction')
    return (transaction._runtime_view_fd,*transaction._runtime_namespace_fds)


def fixed_runtime_command(transaction,kind,request,*,pack_fd=None):
    runtime_launch_fds(transaction)
    if not isinstance(request,str) or len(request.encode())>65536 or not isinstance(json.loads(request),dict):
        raise PermissionError('Fixed Git helper requires a bounded exact request')
    extra=[]
    if kind is FixedGitProgram.CLONE:
        if type(pack_fd) is not int:raise PermissionError('Clone requires its host-pinned pack')
        info=os.fstat(pack_fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink!=1 or info.st_size>64*1024*1024
                or fcntl.fcntl(pack_fd,fcntl.F_GETFL)&os.O_ACCMODE!=os.O_RDONLY):
            raise PermissionError('Clone pack is not a bounded private regular file')
        os.lseek(pack_fd,0,os.SEEK_SET);extra=[str(pack_fd)]
    elif kind is not FixedGitProgram.PULL or pack_fd is not None:
        raise PermissionError('Unexpected fixed Git helper input')
    user,mount,root=transaction._runtime_namespace_fds
    return ['/usr/bin/python3','-I','-S','-c',runtime_script(kind),str(user),str(mount),str(root),request,str(os.getpid()),*extra]


def parse_runtime_output(output):
    try:
        header,body=output.split('\n',1)
        if not header.startswith('AP_RUNTIME_PROOF '):raise ValueError('Missing namespace proof')
        proof=json.loads(header.removeprefix('AP_RUNTIME_PROOF '))
        if (proof['pid']!=1 or any(int(proof[key],16) for key in ('CapEff','CapPrm','CapInh','CapBnd','CapAmb'))
                or proof['NoNewPrivs']!='1'):raise ValueError('Helper privilege proof differs')
        return proof,body
    except (ValueError,TypeError,KeyError) as error:
        raise PermissionError('Fixed Git helper returned invalid privilege proof') from error
