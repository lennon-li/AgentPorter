"""Denied raw canonical paths with verified-FD shims; NOT native UID mapping proof."""
from contextlib import contextmanager
import errno,fcntl,json,os,stat
from pathlib import Path
import pytest
from agentporter import git_remote_policy
from agentporter.git_fetches import ApprovedGitFetches
from agentporter.git_approvals import issue_git_approval
from tests.security.test_nested_repository_scope import configured_nested,metadata
from tests.security.test_development_runtime import runtime_factory
from tests.security.test_approved_git_pull import git
from tests.security.test_git_admission import count


@contextmanager
def denied_canonical(root,monkeypatch,state,*,mapped_alias=False):
 """Only the verified-view loader is shimmed; host raw opens/stats really fail.

 The FD points at the same disposable inode. Native bwrap/Git still execute;
 actual different-UID kernel mapping remains reserved for approved staging.
 """
 import agentporter.sandbox.workspace_projections as views
 real_open=os.open;real_stat=os.stat;real_lstat=os.lstat;path_stat=Path.stat
 pinned=real_open(root,os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC)
 alias=None;realpath=os.path.realpath
 if mapped_alias:
  alias_parent=root.parent/'verified-view-alias';alias_parent.symlink_to(root.parent,target_is_directory=True)
  alias=alias_parent/root.name
 def mapped_realpath(path,*args,**kwargs):
  value=os.fspath(path)
  if alias is not None and isinstance(value,str):
   if value==str(alias) or value.startswith(str(alias)+'/'):return os.path.normpath(value)
   if value.startswith('/proc/self/fd/'):
    pieces=value.split('/');descriptor=pieces[4] if len(pieces)>4 else ''
    if descriptor.isdigit():
     target=os.readlink('/proc/self/fd/'+descriptor)
     if target==str(root) or target.startswith(str(root)+'/'):
      return os.path.normpath(str(alias)+target[len(str(root)):]+('/'+'/'.join(pieces[5:]) if len(pieces)>5 else ''))
  return realpath(path,*args,**kwargs)
 blocked=[];loads=[]
 def raw(path):
  try:value=os.fspath(path)
  except TypeError:return False
  return isinstance(value,str) and (value==str(root) or value.startswith(str(root)+'/'))
 def descendant(path):return raw(path) and os.fspath(path)!=str(root)
 def deny(path):blocked.append(os.fspath(path));raise PermissionError(errno.EACCES,'denied canonical fixture',os.fspath(path))
 def opened(path,flags,*args,**kwargs):
  if raw(path) and not kwargs.get('dir_fd') and (descendant(path) or not flags&os.O_PATH):deny(path)
  return real_open(path,flags,*args,**kwargs)
 def stated(path,*args,**kwargs):
  if descendant(path) and not kwargs.get('dir_fd'):deny(path)
  return real_stat(path,*args,**kwargs)
 def lstated(path,*args,**kwargs):
  if descendant(path) and not kwargs.get('dir_fd'):deny(path)
  return real_lstat(path,*args,**kwargs)
 def pstat(path,*args,**kwargs):
  if path==root:
   values=list(path_stat(path,*args,**kwargs));values[4]=os.getuid()+10000
   return os.stat_result(values)
  return path_stat(path,*args,**kwargs)
 def view(fd,**kwargs):
  assert (os.fstat(fd).st_dev,os.fstat(fd).st_ino)==(os.fstat(pinned).st_dev,os.fstat(pinned).st_ino)
  if kwargs:assert kwargs=={'state_dir':state/'workspace-transactions'}
  loads.append('publication' if kwargs else 'readonly')
  return os.dup(pinned)
 with monkeypatch.context() as patch:
  if alias is not None:patch.setattr(os.path,'realpath',mapped_realpath)
  patch.setattr(os,'open',opened);patch.setattr(os,'stat',stated);patch.setattr(os,'lstat',lstated);patch.setattr(Path,'stat',pstat)
  patch.setattr(views,'open_workspace_projection',view);patch.setattr(views,'open_workspace_publication',view)
  try:yield blocked,loads
  finally:os.close(pinned)


@pytest.mark.parametrize('relative',['.','acceptance/selected'])
@pytest.mark.parametrize('algorithm',['sha1','sha256'])
def test_real_fetch_uses_verified_fds_when_raw_foreign_root_and_child_are_denied(tmp_path,monkeypatch,runtime_factory,relative,algorithm):
 root,selected,other,old,key,manager,remote=configured_nested(tmp_path,monkeypatch,runtime_factory,algorithm=algorithm)
 path=Path(old.authority._config_dir)/'git-remote-policy.json';policy=json.loads(path.read_text())
 policy['grants'][0].update(repository=relative,operations=['fetch']);path.write_text(json.dumps(policy))
 authority=git_remote_policy.load_owner_git_remotes(path.parent,old.registry,old.sandbox.state_dir)
 service=ApprovedGitFetches(old.registry,old.sandbox,authority,manager)
 target=root if relative=='.' else selected;head=git(target,'rev-parse','HEAD');index=(target/'.git/index').read_bytes()
 original=service.sandbox._run_command;observed=[]
 def supervised(**options):
  mount=options.get('workspace_transaction');fd=getattr(mount,'sandbox_workspace_fd',None)
  assert fd is not None,'Foreign canonical data access needs a trusted descriptor before sandbox path inspection'
  info=os.fstat(fd)
  assert (info.st_dev,info.st_ino)==(target_before.st_dev,target_before.st_ino)
  if relative!='.':
   from agentporter.workspaces.leases import workspace_key
   lock=os.open(manager.state_dir/'workspace-transactions'/(workspace_key(info)+'.lock'),os.O_RDWR|os.O_CLOEXEC)
   try:
    with pytest.raises(BlockingIOError):fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
   finally:os.close(lock)
  observed.append(options['argv'][4]);return original(**options)
 target_before=target.stat()
 monkeypatch.setattr(service.sandbox,'_run_command',supervised)
 with denied_canonical(root,monkeypatch,manager.state_dir) as (blocked,loads):
  request=service.prepare('repo','origin','refs/heads/reviewed')
  assert request.to_payload()['repository_path']==str(target)
  assert (request.to_payload()['repository_device'],request.to_payload()['repository_inode'])==(target_before.st_dev,target_before.st_ino)
  assert service.fetch('repo','origin','refs/heads/reviewed',issue_git_approval(key,request))==remote['oid']
  assert not blocked,'A raw EACCES path was attempted; it must not be swallowed as success'
  assert 'readonly' in loads and 'publication' in loads
 assert git(target,'rev-parse','HEAD')==head and (target/'.git/index').read_bytes()==index
 assert git(target,'rev-parse','refs/remotes/origin/reviewed')==remote['oid']
 assert count(manager)==0 and len(observed)>=6


def test_real_nested_worker_pull_and_recovery_use_mapped_data_fds_not_canonical_alias_authority(tmp_path,monkeypatch,runtime_factory):
 from agentporter.sandbox import workspace_git,workspace_recovery
 from agentporter.agents.policy import ExecutionPolicy
 from agentporter.tools.git import create_git_tools
 from agentporter.git_approvals import GitApprovalRequest
 from tests.security.test_nested_repository_scope import WORKER
 from tests.security.test_worker_git_runtime import wait_output,terminal
 from tests.security.custody.test_integration import stopped
 root,selected,other,service,key,manager,remote=configured_nested(tmp_path,monkeypatch,runtime_factory)
 before=metadata(root)
 marker="publication_event('refs_prepared')"
 monkeypatch.setattr(workspace_git,'_IMPORT',workspace_git._IMPORT.replace(marker,marker+'; os._exit(73)'))
 with denied_canonical(root,monkeypatch,manager.state_dir,mapped_alias=True) as (blocked,loads):
  job=manager.start_confined_agent_job(workspace_id='repo',workspace_path=str(root),agent='codex_impl',cmd=['/usr/bin/python3','-c',WORKER.replace('MODE',repr('ff-only'))],policy=ExecutionPolicy.for_workspace(writable=True),timeout_seconds=90)
  prepared=json.loads(wait_output(manager,job,'"status": "prepared"')['stdout'].splitlines()[0]);request=GitApprovalRequest.from_payload(prepared['request'])
  assert request.to_payload()['repository_path']==str(selected)
  tx=manager._job_transactions[job]
  tools=create_git_tools(service.registry,service.sandbox,approved_pulls=service,job_manager=manager)
  result=tools.git_pull('repo',branch='refs/heads/reviewed',job_id=job,request_sha256=request.digest,approval_receipt=issue_git_approval(key,request))
  assert result['status']=='completed',result
  assert terminal(manager,job)['status']=='cleanup_failed',manager.get_output(job)
  assert not manager.active_processes
  for fd in (tx._runtime_view_fd,*tx._runtime_namespace_fds):os.close(fd)
  tx._runtime_view_fd=None;tx._runtime_namespace_fds=None;stopped(tx)
  monkeypatch.setattr(workspace_recovery,'_verify_stopped_service',lambda:None)
  plan=workspace_recovery.recover_workspace(manager.state_dir,root,pull_registry=service.registry,pull_owner_config_dir=service.authority._config_dir)
  assert all(item['inspection']['apply_supported'] for item in plan['git']),plan
  result=workspace_recovery.recover_workspace(manager.state_dir,root,apply=True,restore_deletions=True,expected_plan_sha256=plan['plan_sha256'],pull_registry=service.registry,pull_owner_config_dir=service.authority._config_dir)
  assert result['status']=='recovered' and result['workspace']==str(root)
  assert not blocked,blocked
 after=metadata(root)
 assert all(after[name]==value for name,value in before.items())
 assert all(name.startswith('acceptance/selected/.git/objects/') for name in set(after)-set(before))
 assert count(manager)==0

@pytest.mark.parametrize('published',[False,True])
def test_clone_and_offline_recovery_keep_logical_parent_while_all_data_uses_view_fds(tmp_path,monkeypatch,runtime_factory,published):
 import agentporter.git_clones as clones
 from agentporter.git_clone_recovery import recover_clone
 from agentporter.sandbox import workspace_recovery
 from agentporter.agents.policy import ExecutionPolicy
 from agentporter.tools.git import create_git_tools
 from agentporter.git_approvals import GitApprovalRequest
 from tests.security.test_clone_job_control import configured_clone,CLONE_WORKER
 from tests.security.test_worker_git_runtime import wait_output,terminal
 from tests.security.custody.test_integration import stopped
 root,selected,other,service,key,manager,remote,fetches=configured_clone(tmp_path,monkeypatch,runtime_factory,outer_git=False,algorithm='sha256',existing=True)
 before=metadata(root);empty_inode=(root/'new-clone').stat().st_ino
 if published:
  def interrupted(self):raise RuntimeError('Injected interruption after durable publication before clone outcome resolution')
  monkeypatch.setattr(clones.ClonePublicationIntent,'finish',interrupted)
 worker=CLONE_WORKER if published else CLONE_WORKER+'\nraise SystemExit(7)\n'
 with denied_canonical(root,monkeypatch,manager.state_dir,mapped_alias=True) as (blocked,loads):
  job=manager.start_confined_agent_job(workspace_id='repo',workspace_path=str(root),agent='codex_impl',cmd=['/usr/bin/python3','-c',worker],policy=ExecutionPolicy.for_workspace(writable=True),timeout_seconds=90)
  prepared=json.loads(wait_output(manager,job,'"status": "prepared"')['stdout'].splitlines()[0]);request=GitApprovalRequest.from_payload(prepared['request'])
  assert request.to_payload()['repository_path']==str(root)
  tx=manager._job_transactions[job]
  tools=create_git_tools(service.registry,service.sandbox,approved_pulls=service,job_manager=manager)
  result=tools.git_pull('repo',branch='refs/heads/main',operation='clone',job_id=job,request_sha256=request.digest,approval_receipt=issue_git_approval(key,request))
  assert result['status']=='completed',result
  assert terminal(manager,job)['status']=='cleanup_failed',manager.get_output(job)
  for fd in (tx._runtime_view_fd,*tx._runtime_namespace_fds):os.close(fd)
  tx._runtime_view_fd=None;tx._runtime_namespace_fds=None;stopped(tx)
  monkeypatch.setattr(workspace_recovery,'_verify_stopped_service',lambda:None)
  plan=recover_clone(service.registry,manager.state_dir,service.authority._config_dir,'repo',tx.directory)
  result=recover_clone(service.registry,manager.state_dir,service.authority._config_dir,'repo',tx.directory,apply=True,expected_plan_sha256=plan['plan_sha256'])
  assert result['status']=='recovered' and result['workspace']==str(root)
  assert not blocked,blocked
 assert (root/'new-clone').stat().st_ino==empty_inode and not list((root/'new-clone').iterdir())
 assert metadata(root)==before and count(manager)==0


def test_failed_metadata_fd_revalidation_releases_the_owned_duplicate(tmp_path,monkeypatch,runtime_factory):
 from agentporter.git_commits import _MetadataMount
 root,selected,other,service,key,manager,_=configured_nested(tmp_path,monkeypatch,runtime_factory)
 fd=os.open(selected,os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC)
 try:
  identity=os.fstat(fd);request={'repository_path':str(selected),'repository_device':identity.st_dev,'repository_inode':identity.st_ino,'expected_tree':'a'*40}
  def changed():raise PermissionError('Injected selected identity drift')
  before=set(os.listdir('/proc/self/fd'))
  with pytest.raises(PermissionError,match='identity drift'):_MetadataMount(request,workspace_fd=fd,revalidate=changed)
  assert set(os.listdir('/proc/self/fd'))==before
 finally:os.close(fd)
