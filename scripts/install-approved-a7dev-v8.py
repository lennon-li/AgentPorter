#!/usr/bin/python3
"""Run as operator, never sudo this launcher. Root receives fixed bootstrap code.

The caller must pin this launcher's digest before executing it. The bootstrap
admits only the exact independently reviewed helper/unit/artifact digests. No
mutable repository Python is imported or executed under root.
"""
import os
import subprocess

BOOTSTRAP = r'''
import hashlib,os,pwd,secrets,stat,subprocess
from pathlib import Path
root=Path(__file__).resolve().parent
items=[
 ('install-development-artifact.py','84a53fbfcfe55668a2edda208b0990acf5fd98a6a105a73fb90cc51252e01c58','/usr/local/libexec/agentporter/install-development-artifact.py',0o555),
 ('refresh-development-worker-credentials.py','e99da4cd396336a5fbadbfa7ddee31a95c4350f50295783a758801d6529af289','/usr/local/libexec/agentporter/refresh-development-worker-credentials.py',0o555),
 ('agentporter-dev-credential-sync.service','30bd3a3a9e26f5733d3efd4520c1645a735eddcebb4c0ae55e470b4519922bca','/etc/systemd/system/agentporter-dev-credential-sync.service',0o444),
 ('agentporter-dev-credential-sync.timer','43b7a2200c0a0521e400adb01da93abf759f7ebdb685e4529234b9aa4f3738c2','/etc/systemd/system/agentporter-dev-credential-sync.timer',0o444),
]
verified=[]
os.umask(0o077)
for name,expected,target,mode in items:
 fd=os.open(root/name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
 try:
  before=os.fstat(fd)
  if not stat.S_ISREG(before.st_mode) or before.st_uid!=pwd.getpwnam('operator').pw_uid or before.st_size>1024**2:raise RuntimeError('Unsafe reviewed helper source')
  data=os.read(fd,1024**2+1)
  after=os.fstat(fd)
  if len(data)!=before.st_size or (before.st_size,before.st_mtime_ns,before.st_ctime_ns)!=(after.st_size,after.st_mtime_ns,after.st_ctime_ns) or hashlib.sha256(data).hexdigest()!=expected:raise RuntimeError('Reviewed helper digest mismatch')
  verified.append((target,mode,data))
 finally:os.close(fd)
for target,mode,data in verified:
 path=Path(target);parent=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
 try:
  for part in path.parent.parts[1:]:
   try:os.mkdir(part,0o755,dir_fd=parent)
   except FileExistsError:pass
   child=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=parent);os.close(parent);parent=child
   info=os.fstat(parent)
   if info.st_uid!=0 or info.st_mode&0o022:raise RuntimeError('Untrusted installed helper ancestor')
  temporary='.reviewed-'+secrets.token_hex(16)
  fd=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=parent)
  try:
   with os.fdopen(fd,'wb',closefd=False) as f:f.write(data);f.flush();os.fsync(fd)
   os.fchown(fd,0,0);os.fchmod(fd,mode)
  finally:os.close(fd)
  os.rename(temporary,path.name,src_dir_fd=parent,dst_dir_fd=parent)
 finally:os.close(parent)
env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LANG':'C.UTF-8'}
subprocess.run(['/usr/bin/python3','-I','/usr/local/libexec/agentporter/refresh-development-worker-credentials.py','--apply','--agents','jax,liz,prof,ming,wei,phil,argie'],check=True,env=env,stdin=subprocess.DEVNULL)
subprocess.run(['/usr/bin/python3','-I','/usr/local/libexec/agentporter/install-development-artifact.py','--artifact','/tmp/agentporter-development-candidate-v8.tgz','--sha256','e9b9919f27b9a01e11b8f1274811e035a7d85ecbb809474e83eb6a0a7a89d929','--activate'],check=True,env=env,stdin=subprocess.DEVNULL)
subprocess.run(['/usr/bin/systemctl','daemon-reload'],check=True,env=env)
subprocess.run(['/usr/bin/systemctl','enable','--now','agentporter-dev-credential-sync.timer'],check=True,env=env)
print('Reviewed A7Dev v8 activated; credentials synchronized; production unchanged')
'''

if os.geteuid() == 0:
    raise SystemExit('Run this launcher as operator; it invokes only the reviewed sudo bootstrap')
subprocess.run(['/usr/bin/sudo', '/usr/bin/python3', '-I', '-c', BOOTSTRAP], check=True)
