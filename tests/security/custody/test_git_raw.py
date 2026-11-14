import json,os,stat,subprocess
from pathlib import Path
import pytest
from agentporter.resources import ResourceCleanupError
from agentporter.sandbox import workspace_git_recovery as raw


def fixture(tmp_path):
    root=tmp_path/'repository';root.mkdir()
    subprocess.run(['/usr/bin/git','init','--quiet','--template=',str(root)],check=True,capture_output=True)
    private=tmp_path/'private';private.mkdir(mode=0o700)
    return root,private/'raw-before'


def test_raw_baseline_is_private_durable_and_exact(tmp_path):
    root,operation=fixture(tmp_path)
    baseline=raw.capture_git_baseline(root,operation)
    assert baseline['manifest']==raw.verify_git_baseline(root,operation,baseline['sha256'])
    head=baseline['manifest']['files']['HEAD']
    assert (operation/'blobs'/head['sha256']).read_bytes()==(root/'.git/HEAD').read_bytes()
    assert raw.capture_git_baseline(root,operation)==baseline
    assert not (operation.stat().st_mode&0o077)


@pytest.mark.parametrize('change',['same_bytes_inode','bytes','mode','xattr','new_ref'])
def test_raw_baseline_rejects_later_owner_metadata(tmp_path,change):
    root,operation=fixture(tmp_path);baseline=raw.capture_git_baseline(root,operation)
    head=root/'.git/HEAD'
    if change=='same_bytes_inode':
        substitute=root/'.git/substitute';substitute.write_bytes(head.read_bytes());substitute.replace(head)
    elif change=='bytes':head.write_bytes(b'ref: refs/heads/owner\n')
    elif change=='mode':head.chmod(0o600)
    elif change=='xattr':os.setxattr(head,'user.owner',b'keep')
    else:(root/'.git/refs/heads/owner').write_bytes(b'0'*40+b'\n')
    inode=head.stat().st_ino;data=head.read_bytes()
    with pytest.raises(PermissionError):raw.verify_git_baseline(root,operation,baseline['sha256'])
    assert head.stat().st_ino==inode and head.read_bytes()==data


@pytest.mark.parametrize('entry',['index.lock','symlink','hardlink'])
def test_raw_baseline_rejects_native_locks_and_aliases(tmp_path,entry):
    root,operation=fixture(tmp_path)
    if entry=='symlink':(root/'.git/alias').symlink_to('/dev/null')
    elif entry=='hardlink':os.link(root/'.git/HEAD',root/'.git/alias')
    else:(root/'.git/index.lock').write_bytes(b'owner lock')
    with pytest.raises(PermissionError):raw.capture_git_baseline(root,operation)
    assert not (operation/'baseline.json').exists()


def test_raw_baseline_saved_blob_tampering_refuses_verification(tmp_path):
    root,operation=fixture(tmp_path);baseline=raw.capture_git_baseline(root,operation)
    head=baseline['manifest']['files']['HEAD']
    (operation/'blobs'/head['sha256']).write_bytes(b'bad')
    with pytest.raises(PermissionError):raw.verify_git_baseline(root,operation,baseline['sha256'])


@pytest.mark.parametrize('after_record',[False,True])
def test_raw_baseline_process_death_retries_without_recapturing_owner_changes(tmp_path,after_record):
    root,operation=fixture(tmp_path)
    child=os.fork()
    if child==0:
        original=raw._write_record
        def die(*args):
            if after_record:original(*args)
            os._exit(73)
        raw._write_record=die
        try:raw.capture_git_baseline(root,operation)
        except BaseException:os._exit(74)
        os._exit(75)
    _,status=os.waitpid(child,0);assert os.waitstatus_to_exitcode(status)==73
    baseline=raw.capture_git_baseline(root,operation)
    raw.verify_git_baseline(root,operation,baseline['sha256'])


def test_git_phase_chain_retries_and_rejects_reordering_and_tampering(tmp_path):
    root,operation=fixture(tmp_path);baseline=raw.capture_git_baseline(root,operation)
    payload={'baseline_sha256':baseline['sha256'],'guard_sha256':'a'*64}
    first=raw.record_git_phase(root,operation,'guarded',payload)
    assert raw.record_git_phase(root,operation,'guarded',payload)==first
    with pytest.raises(PermissionError):raw.record_git_phase(root,operation,'import_returned',{})
    raw.record_git_phase(root,operation,'import_started',{'plan':{}})
    raw.record_git_phase(root,operation,'import_returned',{'exit_code':0})
    assert len(raw.inspect_git_phases(root,operation)['events'])==3
    first_record=operation/'phase-00000000.json'
    changed=json.loads(first_record.read_text());changed['payload']['guard_sha256']='b'*64
    first_record.write_text(json.dumps(changed))
    with pytest.raises(PermissionError):raw.inspect_git_phases(root,operation)


def test_git_phase_process_death_after_exposure_acknowledges_same_event(tmp_path):
    root,operation=fixture(tmp_path);baseline=raw.capture_git_baseline(root,operation)
    payload={'baseline_sha256':baseline['sha256'],'guard_sha256':'a'*64}
    child=os.fork()
    if child==0:
        original=raw._write_record
        def die(*args):original(*args);os._exit(73)
        raw._write_record=die
        try:raw.record_git_phase(root,operation,'guarded',payload)
        except BaseException:os._exit(74)
        os._exit(75)
    _,status=os.waitpid(child,0);assert os.waitstatus_to_exitcode(status)==73
    raw.record_git_phase(root,operation,'guarded',payload)
    assert len(raw.inspect_git_phases(root,operation)['events'])==1


def imported_history(tmp_path):
    from tests.security.custody.test_native_history import history,private_git
    root,item=history(tmp_path)
    (root/'ordinary').write_text('agent edit')
    private_git(item,'add','ordinary');private_git(item,'commit','-qm','raw recovery fixture')
    item.prepare();item.guard_publication();item.publish()
    return root,item


def test_successful_native_import_has_before_after_and_no_automatic_replay(tmp_path):
    root,item=imported_history(tmp_path)
    try:
        events=raw.inspect_git_phases(root,item.raw_baseline_directory)['events']
        assert [event['phase'] for event in events]==['guarded','import_started','import_returned']
        after=events[-1]['payload']['after_sha256']
        raw.verify_git_baseline(root,item.raw_baseline_directory.parent/'raw-after',after)
        with pytest.raises(ResourceCleanupError,match='prior uncertain lifecycle'):item.publish()
        item.finish();assert not item.guard.exists()
    finally:item.close()


def test_git_guard_retirement_preserves_same_byte_owner_replacement(tmp_path,monkeypatch):
    from agentporter.sandbox import workspace_custody as custody
    root,item=imported_history(tmp_path)
    owner=[];original=custody._rename_noreplace
    def race(source,name,destination,destname):
        if name==item.guard.name and not owner:
            substitute=item.guard.with_name('owner-guard')
            substitute.write_bytes(item.guard.read_bytes());substitute.chmod(0o600)
            substitute.replace(item.guard);owner.append(item.guard.stat().st_ino)
        return original(source,name,destination,destname)
    monkeypatch.setattr(custody,'_rename_noreplace',race)
    try:
        with pytest.raises((OSError,PermissionError)):item.finish()
        assert owner and item.guard.stat().st_ino==owner[0]
        assert item.guard.read_bytes()==(item.raw_baseline_directory/'git-guard.backup').read_bytes()
    finally:item.close()


def test_git_guard_capture_process_death_is_idempotently_resumed(tmp_path):
    from agentporter.sandbox import workspace_custody as custody
    root,item=imported_history(tmp_path)
    try:
        child=os.fork()
        if child==0:
            original=custody._rename_noreplace
            def die(*args):original(*args);os._exit(73)
            custody._rename_noreplace=die
            try:item.finish()
            except BaseException:os._exit(74)
            os._exit(75)
        _,status=os.waitpid(child,0);assert os.waitstatus_to_exitcode(status)==73
        item.finish();assert not item.guard.exists()
        captured=list((item.guard.parent.parent/'git-guard-custody').glob('*/captured'))
        assert len(captured)==1
        assert captured[0].read_bytes()==(item.raw_baseline_directory/'git-guard.backup').read_bytes()
    finally:item.close()


def test_same_byte_replaced_guard_blocks_import_before_started_phase(tmp_path):
    from tests.security.custody.test_native_history import history,private_git
    root,item=history(tmp_path)
    try:
        (root/'ordinary').write_text('agent edit')
        private_git(item,'add','ordinary');private_git(item,'commit','-qm','guard fixture')
        item.prepare();item.guard_publication()
        substitute=item.guard.with_name('owner-guard')
        substitute.write_bytes(item.guard.read_bytes());substitute.chmod(0o600);substitute.replace(item.guard)
        owner=item.guard.stat().st_ino
        with pytest.raises(ResourceCleanupError,match='guard identity changed'):item.publish()
        assert item.guard.stat().st_ino==owner
        assert [event['phase'] for event in raw.inspect_git_phases(root,item.raw_baseline_directory)['events']]==['guarded']
        raw.verify_git_baseline(root,item.raw_baseline_directory,item.raw_baseline['sha256'])
    finally:item.close()


def test_native_events_bind_staged_index_and_head_inodes_before_publication(tmp_path):
    root,item=imported_history(tmp_path)
    try:
        report=raw.inspect_native_git_phases(root,item.native_events,raw._digest(item.plan))
        assert report['last_stage']=='cleanup_finished'
        stages={event['stage']:event for event in report['events']}
        assert 'config' not in stages['before_locks']['files']
        locks=stages['refs_prepared']['files']
        assert 'index.lock' in locks and 'HEAD.lock' in locks
        assert any(name.startswith('refs/') and name.endswith('.lock') for name in locks)
        for prefix,target in (('.agentporter-index-','index'),('.agentporter-head-','HEAD')):
            intent=stages[target.lower()+'_publish_intent']['files']
            staged=[record for name,record in intent.items() if name.startswith(prefix)]
            assert len(staged)==1
            applied=stages[target.lower()+'_published']['files'][target]
            assert staged[0]['signature'][:2]==applied['signature'][:2]
            assert staged[0]['sha256']==applied['sha256']
        assert report['reconciliation_supported'] is False
        assert raw.inspect_git_phases(root,item.raw_baseline_directory)['events'][-1]['payload']['native_events_sha256']==report['sha256']
        item.finish()
    finally:item.close()


@pytest.mark.parametrize('stage',['before_locks','index_staged','refs_prepared','refs_commit_intent',
                                'refs_committed','index_publish_intent','index_published',
                                'head_publish_intent','head_published','cleanup_finished'])
def test_native_process_death_leaves_verifiable_exact_phase(tmp_path,monkeypatch,stage):
    from tests.security.custody.test_native_history import history,private_git
    from agentporter.sandbox import workspace_git as module
    root,item=history(tmp_path)
    try:
        (root/'ordinary').write_text('interrupted agent edit')
        private_git(item,'add','ordinary');private_git(item,'commit','-qm','native phase interruption')
        item.prepare();item.guard_publication()
        marker="publication_event('"+stage+"')"
        assert module._IMPORT.count(marker)==1
        program=module._IMPORT.replace(marker,marker+'; os._exit(73)')
        compile(program,'<native-phase-crash>','exec')
        monkeypatch.setattr(module,'_IMPORT',program)
        with pytest.raises(ResourceCleanupError):item.publish()
        report=raw.inspect_native_git_phases(root,item.native_events,raw._digest(item.plan))
        assert report['last_stage']==stage
        assert item.guard.exists()
        assert report['reconciliation_supported'] is False
        coarse=raw.inspect_git_phases(root,item.raw_baseline_directory)['events']
        assert coarse[-1]['payload']['exit_code']==73
        with pytest.raises(ResourceCleanupError,match='prior uncertain lifecycle'):item.publish()
    finally:item.close()


def test_native_journal_blob_tampering_blocks_inspection(tmp_path):
    root,item=imported_history(tmp_path)
    try:
        report=raw.inspect_native_git_phases(root,item.native_events,raw._digest(item.plan))
        digest=report['events'][0]['files']['HEAD']['sha256']
        (item.native_events/'blobs'/digest).write_bytes(b'changed')
        with pytest.raises(PermissionError):raw.inspect_native_git_phases(root,item.native_events,raw._digest(item.plan))
    finally:item.close()


@pytest.mark.parametrize('stage',['stash_publish_intent','stash_published','stash_delete_intent'])
def test_native_stash_process_death_has_durable_phase_evidence(tmp_path,monkeypatch,stage):
    from tests.security.custody.test_native_history import history,private_git,git,setup,RecordingResources,BubblewrapSandbox
    from agentporter.sandbox import workspace_git as module
    if stage=='stash_delete_intent':
        root,_,initial=setup(tmp_path)
        (root/'ordinary').write_text('initial owner stash')
        git(root,'stash','push','-m','baseline')
        sandbox=BubblewrapSandbox(initial.state_dir,transactional_writes=True)
        sandbox.resources=RecordingResources()
        (sandbox.state_dir/'workspace-transactions').mkdir(exist_ok=True)
        item=module.WorkspaceGitHistory(root,tmp_path/'private-history',sandbox)
        private_git(item,'stash','clear')
    else:
        root,item=history(tmp_path)
        (root/'ordinary').write_text('private stash')
        private_git(item,'stash','push','-m','phase fixture')
    try:
        item.prepare();item.guard_publication()
        assert item.changed and item.plan['publication_time']>0
        marker="publication_event('"+stage+"')"
        assert module._IMPORT.count(marker)==1
        monkeypatch.setattr(module,'_IMPORT',module._IMPORT.replace(marker,marker+'; os._exit(73)'))
        with pytest.raises(ResourceCleanupError):item.publish()
        report=raw.inspect_native_git_phases(root,item.native_events,raw._digest(item.plan))
        assert report['last_stage']==stage and report['outcome_uncertain']
        assert item.guard.exists()
        assert raw.inspect_git_phases(root,item.raw_baseline_directory)['events'][-1]['payload']['exit_code']==73
    finally:item.close()


def test_reconciliation_distinguishes_created_native_refs_from_observations(tmp_path):
    root,item=imported_history(tmp_path)
    try:
        plan=raw.inspect_git_reconciliation(root,item.raw_baseline_directory.parent,item.guard)
        states={entry['path']:entry['state'] for entry in plan['files']}
        assert states['index']=='descriptor_bound_candidate'
        assert states['HEAD']=='descriptor_bound_candidate'
        assert states['config']=='baseline'
        assert any(path.startswith('refs/heads/') and state=='descriptor_bound_candidate' for path,state in states.items())
        assert plan['native_tail_anchored'] and plan['apply_supported']
        assert item.guard.exists()
    finally:item.close()


def test_reconciliation_refuses_equal_byte_owner_index_replacement(tmp_path):
    root,item=imported_history(tmp_path)
    try:
        target=root/'.git/index';substitute=root/'.git/owner-index'
        data=target.read_bytes();info=target.stat();substitute.write_bytes(data)
        substitute.chmod(stat.S_IMODE(info.st_mode));os.utime(substitute,ns=(info.st_atime_ns,info.st_mtime_ns))
        substitute.replace(target);owner=target.stat().st_ino
        plan=raw.inspect_git_reconciliation(root,item.raw_baseline_directory.parent,item.guard)
        entry=next(item for item in plan['files'] if item['path']=='index')
        assert entry['state']=='owner_or_unrecorded_conflict'
        assert target.stat().st_ino==owner and target.read_bytes()==data
    finally:item.close()


def test_descriptor_binding_does_not_bless_owner_stage_path_swap(tmp_path,monkeypatch):
    from tests.security.custody.test_native_history import history,private_git
    from agentporter.sandbox import workspace_git as module
    root,item=history(tmp_path)
    try:
        (root/'ordinary').write_text('staged swap fixture')
        private_git(item,'add','ordinary');private_git(item,'commit','-qm','staged swap')
        item.prepare();item.guard_publication()
        marker="    publication_event('index_publish_intent')"
        injection="""    original_info = os.stat(git_root + '/' + staged_index)
    with open(git_root + '/' + staged_index, 'rb') as original_file:
        owner_bytes = original_file.read()
    with open(git_root + '/.owner-stage', 'xb') as owner_file:
        owner_file.write(owner_bytes)
    os.chmod(git_root + '/.owner-stage', stat.S_IMODE(original_info.st_mode))
    os.utime(git_root + '/.owner-stage', ns=(original_info.st_atime_ns, original_info.st_mtime_ns))
    os.replace(git_root + '/.owner-stage', git_root + '/' + staged_index)
"""
        assert module._IMPORT.count(marker)==1
        program=module._IMPORT.replace(marker,injection+marker);compile(program,'<owner-stage-swap>','exec')
        monkeypatch.setattr(module,'_IMPORT',program)
        original_index=(root/'.git/index').stat().st_ino
        with pytest.raises(ResourceCleanupError):item.publish()
        plan=raw.inspect_git_reconciliation(root,item.raw_baseline_directory.parent,item.guard)
        entry=next(item for item in plan['files'] if item['path']=='index')
        assert entry['state']=='verified_before_copy'
        assert (item.original_directory/'original-index/captured').stat().st_ino==original_index
        copy=json.loads((item.original_directory/'index-attempt-0000.json').read_text())
        assert (root/'.git/index').stat().st_ino==copy['signature'][1]
        retained=[entry for entry in plan['files'] if entry['path'].startswith('.agentporter-index-')]
        assert len(retained)==1 and retained[0]['state']=='native_observation_unproven'
        assert (root/'.git'/retained[0]['path']).is_file()
        assert item.guard.exists()
    finally:item.close()


def test_offline_combined_plan_inspects_git_and_retains_all_guards(tmp_path,monkeypatch):
    from tests.security.custody.test_native_history import setup,BubblewrapSandbox,RecordingResources
    from tests.security.custody.test_integration import stopped
    from agentporter.sandbox import workspace_git as module,workspace_recovery as recovery
    root,_,initial=setup(tmp_path)
    initial.state_dir.chmod(0o700)
    sandbox=BubblewrapSandbox(initial.state_dir,transactional_writes=True)
    sandbox.resources=RecordingResources()
    from tests.security.custody.authorization_seams import allow_one_history_publication_for_recovery
    history_seam=allow_one_history_publication_for_recovery(monkeypatch,root)
    marker="publication_event('index_published')"
    assert module._IMPORT.count(marker)==1
    monkeypatch.setattr(module,'_IMPORT',module._IMPORT.replace(marker,marker+'; os._exit(73)'))
    with pytest.raises(ResourceCleanupError):
        sandbox.run(str(root),['/bin/sh','-c',
            'printf "combined recovery fixture" > ordinary && git add ordinary && git commit -qm "combined recovery"'])
    assert len(history_seam)==1
    assert len(sandbox._unresolved_transactions)==1
    transaction=sandbox._unresolved_transactions[0]
    guard=next(iter(transaction.git_histories.values())).guard
    stopped(transaction)
    monkeypatch.setattr(recovery,'_verify_stopped_service',lambda:None)
    descriptor=os.open(root,raw._FLAGS)
    try:before=raw._snapshot(descriptor,allow_locks=True)
    finally:os.close(descriptor)
    plan=recovery.recover_workspace(sandbox.state_dir,root)
    assert len(plan['git'])==1,plan
    assert plan['git'][0]['inspection']['status']=='inspection_only',plan
    assert plan['git'][0]['inspection']['last_stage']=='index_published'
    assert plan['git'][0]['inspection']['apply_supported']
    assert guard.exists() and transaction._pending.exists()
    descriptor=os.open(root,raw._FLAGS)
    try:assert before==raw._snapshot(descriptor,allow_locks=True)
    finally:os.close(descriptor)


def metadata_fixture(tmp_path):
    from agentporter.sandbox import git_metadata_custody as bridge
    root,baseline_path=fixture(tmp_path)
    baseline=raw.capture_git_baseline(root,baseline_path)['manifest']
    record=raw._native_record(baseline['files']['HEAD'])
    record.update(mode=stat.S_IMODE(record['signature'][2]),mtime_ns=record['signature'][5])
    identity={key:baseline[key] for key in ('workspace','git')}
    parents={key:value['identity'] for key,value in baseline['directories'].items()}
    operation=baseline_path.parent/'metadata-custody'
    support=bridge.preflight_git_entry(root,'HEAD',operation,identity=identity,parents=parents)
    return bridge,root,operation,identity,parents,record,support


def test_git_metadata_custody_retains_and_restores_exact_head_inode(tmp_path):
    bridge,root,operation,identity,parents,record,support=metadata_fixture(tmp_path)
    inode=(root/'.git/HEAD').stat().st_ino
    result=bridge.capture_git_entry(root,'HEAD',operation,identity=identity,parents=parents,
                                    expected_record=record,expected_support=support)
    assert result['state']=='captured_expected' and not (root/'.git/HEAD').exists()
    assert (operation/'captured').stat().st_ino==inode
    bridge.restore_git_entry(root,'HEAD',operation,identity=identity,parents=parents)
    assert (root/'.git/HEAD').stat().st_ino==inode
    from agentporter.sandbox.workspace_delta import _require_public_path
    with pytest.raises(PermissionError):_require_public_path('.git/HEAD')


@pytest.mark.parametrize('path',['refs/remotes/origin/main','refs/notes/note','packed-refs','config','hooks/pre-commit',
                               'objects/ab/file','../HEAD','/HEAD','logs/refs/heads/../HEAD'])
def test_git_metadata_adapter_never_grants_raw_ref_or_protected_mutation(tmp_path,path):
    bridge,root,operation,identity,parents,record,support=metadata_fixture(tmp_path)
    original=(root/'.git/HEAD').read_bytes()
    with pytest.raises(PermissionError):
        bridge.preflight_git_entry(root,path,operation.parent/'rejected',identity=identity,parents=parents)
    assert (root/'.git/HEAD').read_bytes()==original


@pytest.mark.parametrize('content',[b'owner different bytes',None])
def test_git_metadata_capture_preserves_later_owner_inode(tmp_path,monkeypatch,content):
    from agentporter.sandbox import workspace_custody as custody
    bridge,root,operation,identity,parents,record,support=metadata_fixture(tmp_path)
    original=custody._rename_noreplace;owner=[]
    def race(source,name,destination,destname):
        if name=='HEAD' and not owner:
            later=root/'.git/owner-head';later.write_bytes(content if content is not None else (root/'.git/HEAD').read_bytes())
            later.replace(root/'.git/HEAD');owner.append((root/'.git/HEAD').stat().st_ino)
        return original(source,name,destination,destname)
    monkeypatch.setattr(custody,'_rename_noreplace',race)
    with pytest.raises(PermissionError):
        bridge.capture_git_entry(root,'HEAD',operation,identity=identity,parents=parents,
                                 expected_record=record,expected_support=support)
    assert (root/'.git/HEAD').stat().st_ino==owner[0]


def test_git_metadata_custody_process_death_after_capture_resumes(tmp_path):
    from agentporter.sandbox import workspace_custody as custody
    bridge,root,operation,identity,parents,record,support=metadata_fixture(tmp_path)
    child=os.fork()
    if child==0:
        original=custody._rename_noreplace
        def die(*args):original(*args);os._exit(73)
        custody._rename_noreplace=die
        try:bridge.capture_git_entry(root,'HEAD',operation,identity=identity,parents=parents,
                                     expected_record=record,expected_support=support)
        except BaseException:os._exit(74)
        os._exit(75)
    _,status=os.waitpid(child,0);assert os.waitstatus_to_exitcode(status)==73
    assert bridge.inspect_git_entry(root,'HEAD',operation,identity=identity,parents=parents)['expected']
    bridge.restore_git_entry(root,'HEAD',operation,identity=identity,parents=parents)
    assert (root/'.git/HEAD').stat().st_ino==record['signature'][1]


def test_git_metadata_custody_refuses_storage_inside_workspace(tmp_path):
    bridge,root,operation,identity,parents,record,support=metadata_fixture(tmp_path)
    (root/'private').mkdir(mode=0o700)
    with pytest.raises(PermissionError,match='entire workspace'):
        bridge.preflight_git_entry(root,'HEAD',root/'private/custody',identity=identity,parents=parents)


def test_git_metadata_custody_refuses_different_mount_before_mutation(tmp_path,monkeypatch):
    from agentporter.sandbox import workspace_custody as custody
    bridge,root,operation,identity,parents,record,support=metadata_fixture(tmp_path)
    original=custody._mount_id
    monkeypatch.setattr(custody,'_mount_id',lambda fd:original(fd)+(1 if os.readlink('/proc/self/fd/'+str(fd)).endswith('metadata-custody') else 0))
    with pytest.raises(PermissionError,match='mount'):
        bridge.capture_git_entry(root,'HEAD',operation,identity=identity,parents=parents,
                                 expected_record=record,expected_support=support)
    assert (root/'.git/HEAD').stat().st_ino==record['signature'][1]


def test_git_metadata_restore_preserves_new_destination_and_retained_original(tmp_path):
    bridge,root,operation,identity,parents,record,support=metadata_fixture(tmp_path)
    bridge.capture_git_entry(root,'HEAD',operation,identity=identity,parents=parents,
                             expected_record=record,expected_support=support)
    (root/'.git/HEAD').write_bytes(b'owner new HEAD');owner=(root/'.git/HEAD').stat().st_ino
    with pytest.raises(PermissionError):
        bridge.restore_git_entry(root,'HEAD',operation,identity=identity,parents=parents)
    assert (root/'.git/HEAD').stat().st_ino==owner
    assert (root/'.git/HEAD').read_bytes()==b'owner new HEAD'
    assert (operation/'captured').stat().st_ino==record['signature'][1]


def test_git_metadata_changed_parent_is_refused_before_capture(tmp_path):
    from agentporter.sandbox import git_metadata_custody as bridge
    root,baseline_path=fixture(tmp_path)
    (root/'.git/logs/refs').mkdir(parents=True)
    target=root/'.git/logs/refs/stash';target.write_bytes(b'initial synthetic reflog')
    baseline=raw.capture_git_baseline(root,baseline_path)['manifest']
    record=raw._native_record(baseline['files']['logs/refs/stash'])
    record.update(mode=stat.S_IMODE(record['signature'][2]),mtime_ns=record['signature'][5])
    identity={key:baseline[key] for key in ('workspace','git')}
    parents={key:value['identity'] for key,value in baseline['directories'].items()}
    operation=baseline_path.parent/'metadata-custody'
    support=bridge.preflight_git_entry(root,'logs/refs/stash',operation,identity=identity,parents=parents)
    (root/'.git/logs/refs').rename(root/'.git/logs/original-refs')
    (root/'.git/logs/refs').mkdir();target.write_bytes(b'owner new reflog')
    with pytest.raises(PermissionError,match='parent'):
        bridge.capture_git_entry(root,'logs/refs/stash',operation,identity=identity,parents=parents,
                                 expected_record=record,expected_support=support)
    assert target.read_bytes()==b'owner new reflog'
    assert (root/'.git/logs/original-refs/stash').stat().st_ino==record['signature'][1]


def test_git_metadata_root_replacement_is_refused(tmp_path):
    bridge,root,operation,identity,parents,record,support=metadata_fixture(tmp_path)
    (root/'.git').rename(root/'original-git');(root/'.git').mkdir()
    (root/'.git/HEAD').write_bytes(b'owner metadata root')
    with pytest.raises(PermissionError,match='metadata root'):
        bridge.capture_git_entry(root,'HEAD',operation,identity=identity,parents=parents,
                                 expected_record=record,expected_support=support)
    assert (root/'.git/HEAD').read_bytes()==b'owner metadata root'
    assert (root/'original-git/HEAD').stat().st_ino==record['signature'][1]


def test_git_metadata_restore_cannot_reinterpret_intent_as_another_path(tmp_path):
    bridge,root,operation,identity,parents,record,support=metadata_fixture(tmp_path)
    bridge.capture_git_entry(root,'HEAD',operation,identity=identity,parents=parents,
                             expected_record=record,expected_support=support)
    with pytest.raises(PermissionError,match='intent path'):
        bridge.restore_git_entry(root,'index',operation,identity=identity,parents=parents)
    assert not (root/'.git/HEAD').exists()
    assert (operation/'captured').stat().st_ino==record['signature'][1]


def unchanged_git_interruption(tmp_path,monkeypatch,native_stage='before_locks'):
    from tests.security.custody.test_native_history import setup,BubblewrapSandbox,RecordingResources
    from tests.security.custody.test_integration import stopped
    from agentporter.sandbox import workspace_git as module,workspace_recovery as recovery
    from agentporter.tools.jobs import JobManager
    root,_,initial=setup(tmp_path);initial.state_dir.chmod(0o700)
    sandbox=BubblewrapSandbox(initial.state_dir,transactional_writes=True);sandbox.resources=RecordingResources()
    from tests.security.custody.authorization_seams import allow_one_history_publication_for_recovery
    history_seam=allow_one_history_publication_for_recovery(monkeypatch,root)
    marker="publication_event('"+native_stage+"')"
    assert module._IMPORT.count(marker)==1
    with monkeypatch.context() as patch:
        patch.setattr(module,'_IMPORT',module._IMPORT.replace(marker,marker+'; os._exit(73)'))
        with pytest.raises(ResourceCleanupError):
            sandbox.run(str(root),['/bin/sh','-c',
                'printf "recovery before native mutation" > ordinary && git add ordinary && git commit -qm "before recovery"'])
    assert len(history_seam)==1
    transaction=sandbox._unresolved_transactions[0]
    history=next(iter(transaction.git_histories.values()));guard=history.guard
    manager=JobManager(sandbox.state_dir)
    connection=manager._get_db()
    with connection:
        connection.execute("INSERT INTO jobs(job_id,workspace_id,status,argv,created_at,workspace_transaction) VALUES ('owned','fixture','cleanup_failed','[]',0,?)",(str(transaction.directory),))
        connection.execute("INSERT INTO jobs(job_id,workspace_id,status,argv,created_at,workspace_transaction) VALUES ('foreign','other','cleanup_failed','[]',0,'/other')")
        connection.execute("INSERT INTO job_admissions VALUES ('own','owned',0,0)")
        connection.execute("INSERT INTO job_admissions VALUES ('other','foreign',0,0)")
        connection.execute("INSERT INTO job_admissions VALUES ('unbound',NULL,0,0)")
    connection.close()
    stopped(transaction)
    monkeypatch.setattr(recovery,'_verify_stopped_service',lambda:None)
    return root,sandbox,transaction,guard,manager,history


def test_verified_unchanged_git_recovers_worktree_and_both_guards(tmp_path,monkeypatch):
    from agentporter.sandbox import workspace_recovery as recovery,workspace_transactions as transactions
    from tests.security.custody.test_integration import assert_jobs
    root,sandbox,tx,guard,manager,history=unchanged_git_interruption(tmp_path,monkeypatch)
    plan=recovery.recover_workspace(sandbox.state_dir,root)
    assert plan['git'][0]['inspection']['apply_supported']
    result=recovery.recover_workspace(sandbox.state_dir,root,apply=True,restore_deletions=True,
                                      expected_plan_sha256=plan['plan_sha256'])
    assert result['status']=='recovered' and result['endpoint']=='before'
    assert (root/'ordinary').read_text()=='initial'
    raw.verify_git_baseline(root,history.raw_baseline_directory,history.raw_baseline['sha256'])
    assert not guard.exists() and not tx._pending.exists();assert_jobs(manager)
    followup=transactions.WorkspaceTransaction(root,sandbox.state_dir/'workspace-transactions',git_sandbox=sandbox)
    followup.close()


@pytest.mark.parametrize('stage',['before_backup_link','after_backup_link','after_original_displacement','before_receipt','after_receipt','after_db_commit','after_git_capture','after_workspace_capture'])
def test_unchanged_git_recovery_second_process_death_resumes(tmp_path,monkeypatch,stage):
    from agentporter.sandbox import workspace_recovery as recovery,workspace_transactions as transactions,workspace_custody as custody
    from agentporter.workspaces.leases import mutation_lease
    from tests.security.custody.test_integration import assert_jobs
    root,sandbox,tx,guard,manager,history=unchanged_git_interruption(tmp_path,monkeypatch)
    child=os.fork()
    if child==0:
        from agentporter.sandbox import recovery_guards
        backup_link=recovery_guards._publish_restore_fd
        def linked(*args):
            if stage=='before_backup_link':os._exit(73)
            result=backup_link(*args)
            if stage=='after_backup_link':os._exit(73)
            return result
        recovery_guards._publish_restore_fd=linked
        original_receipt=recovery._write_receipt
        def receipt(path,data):
            if data.get('status')=='recovered':
                if stage=='before_receipt':os._exit(73)
                result=original_receipt(path,data)
                if stage=='after_receipt':os._exit(73)
                return result
            return original_receipt(path,data)
        recovery._write_receipt=receipt
        if stage=='after_db_commit':
            connect=recovery.sqlite3.connect
            class Crash(recovery.sqlite3.Connection):
                def __exit__(self,*args):super().__exit__(*args);os._exit(73)
            recovery.sqlite3.connect=lambda *args,**kwargs:connect(*args,**kwargs,factory=Crash)
        original_move=custody._rename_noreplace
        def moved(source,name,destination,destname):
            result=original_move(source,name,destination,destname)
            if stage=='after_git_capture' and name==guard.name:os._exit(73)
            if stage=='after_workspace_capture' and name==tx._pending.name:os._exit(73)
            if stage=='after_original_displacement' and name=='HEAD':os._exit(73)
            return result
        custody._rename_noreplace=moved
        try:
            plan=recovery.recover_workspace(sandbox.state_dir,root)
            recovery.recover_workspace(sandbox.state_dir,root,apply=True,restore_deletions=True,
                                       expected_plan_sha256=plan['plan_sha256'])
        except BaseException:os._exit(74)
        os._exit(75)
    _,status=os.waitpid(child,0);assert os.waitstatus_to_exitcode(status)==73
    with pytest.raises(ResourceCleanupError):
        transactions.WorkspaceTransaction(root,sandbox.state_dir/'workspace-transactions')
    with pytest.raises(ResourceCleanupError):
        with mutation_lease(root,sandbox.state_dir/'workspace-transactions'):pass
    plan=recovery.recover_workspace(sandbox.state_dir,root)
    assert plan['git'][0]['inspection']['apply_supported']
    result=recovery.recover_workspace(sandbox.state_dir,root,apply=True,restore_deletions=True,
                                      expected_plan_sha256=plan['plan_sha256'])
    assert result['status']=='recovered' and not guard.exists() and not tx._pending.exists()
    assert (root/'ordinary').read_text()=='initial';assert_jobs(manager)
    raw.verify_git_baseline(root,history.raw_baseline_directory,history.raw_baseline['sha256'])
    followup=transactions.WorkspaceTransaction(root,sandbox.state_dir/'workspace-transactions',git_sandbox=sandbox)
    followup.close()


def test_before_recovery_owner_git_drift_rejects_before_worktree_changes(tmp_path,monkeypatch):
    from agentporter.sandbox import workspace_recovery as recovery
    root,sandbox,tx,guard,manager,history=unchanged_git_interruption(tmp_path,monkeypatch)
    (root/'.git/refs/heads/owner').write_bytes(b'0'*40+b'\n')
    original=(root/'ordinary').stat().st_ino;data=(root/'ordinary').read_bytes()
    plan=recovery.recover_workspace(sandbox.state_dir,root)
    assert not plan['git'][0]['inspection']['apply_supported']
    with pytest.raises(PermissionError,match='coherent Git apply remains unsupported'):
        recovery.recover_workspace(sandbox.state_dir,root,apply=True,restore_deletions=True,expected_plan_sha256=plan['plan_sha256'])
    assert (root/'ordinary').stat().st_ino==original and (root/'ordinary').read_bytes()==data
    assert guard.exists() and tx._pending.exists()
    connection=manager._get_db()
    try:
        assert connection.execute("SELECT status FROM jobs WHERE job_id='owned'").fetchone()[0]=='cleanup_failed'
        assert connection.execute("SELECT 1 FROM job_admissions WHERE token='own'").fetchone()
    finally:connection.close()


def test_before_recovery_same_byte_workspace_guard_swap_invalidates_reviewed_plan(tmp_path,monkeypatch):
    from agentporter.sandbox import workspace_recovery as recovery
    root,sandbox,tx,guard,manager,history=unchanged_git_interruption(tmp_path,monkeypatch)
    plan=recovery.recover_workspace(sandbox.state_dir,root)
    later=tx._pending.with_name('owner-workspace-guard')
    later.write_bytes(tx._pending.read_bytes());later.chmod(0o600);later.replace(tx._pending)
    owner=tx._pending.stat().st_ino;data=(root/'ordinary').read_bytes()
    with pytest.raises(PermissionError,match='exact reviewed plan'):
        recovery.recover_workspace(sandbox.state_dir,root,apply=True,restore_deletions=True,expected_plan_sha256=plan['plan_sha256'])
    assert tx._pending.stat().st_ino==owner and (root/'ordinary').read_bytes()==data


def test_changed_retirement_bundle_invalidates_reviewed_recovery_plan(tmp_path,monkeypatch):
    from agentporter.sandbox import workspace_recovery as recovery,recovery_guards
    from agentporter.workspaces.leases import workspace_key
    root,sandbox,tx,guard,manager,history=unchanged_git_interruption(tmp_path,monkeypatch)
    initial=recovery.recover_workspace(sandbox.state_dir,root)
    base=recovery_guards.location(sandbox.state_dir,workspace_key(root.stat()),tx.directory.name)
    record=raw.inspect_git_phases(root,history.raw_baseline_directory)['events'][0]['payload']['guard_record']
    recovery_guards.prepare(base,state=sandbox.state_dir,workspace=root,transaction=tx.directory,
        journal=tx._pending,journal_hash=initial['journal_sha256'],journal_signature=initial['journal_signature'],
        git_guards=[{'path':guard,'record':record}])
    plan=recovery.recover_workspace(sandbox.state_dir,root)
    assert plan['recovery_bundle_sha256']
    active=base/'active.json';changed=json.loads(active.read_text())
    changed['guards'][0]['record']['mtime_ns']+=1
    active.write_text(json.dumps(changed))
    data=(root/'ordinary').read_bytes()
    with pytest.raises(PermissionError,match='exact reviewed plan'):
        recovery.recover_workspace(sandbox.state_dir,root,apply=True,restore_deletions=True,expected_plan_sha256=plan['plan_sha256'])
    assert (root/'ordinary').read_bytes()==data and guard.exists() and tx._pending.exists()


@pytest.mark.parametrize('stage',['guard_created','index_staged'])
def test_recovery_captures_proven_native_temporaries_before_any_ref_commit(tmp_path,monkeypatch,stage):
    from agentporter.sandbox import workspace_recovery as recovery,workspace_transactions as transactions
    from tests.security.custody.test_integration import assert_jobs
    root,sandbox,tx,guard,manager,history=unchanged_git_interruption(tmp_path,monkeypatch,native_stage=stage)
    plan=recovery.recover_workspace(sandbox.state_dir,root)
    inspected=plan['git'][0]['inspection']
    assert inspected['apply_supported'],inspected
    paths={entry['path'] for entry in inspected['metadata_capture_plan']}
    assert 'index.lock' in paths
    if stage!='guard_created':
        assert 'HEAD.lock' in paths
        assert any(path.startswith('.agentporter-index-') for path in paths)
    result=recovery.recover_workspace(sandbox.state_dir,root,apply=True,restore_deletions=True,
                                      expected_plan_sha256=plan['plan_sha256'])
    assert result['status']=='recovered' and (root/'ordinary').read_text()=='initial'
    assert not tx._pending.exists() and not guard.exists();assert_jobs(manager)
    raw.verify_git_baseline(root,history.raw_baseline_directory,history.raw_baseline['sha256'])
    retained=list((history.raw_baseline_directory.parent/'metadata-rollback').glob('*/captured'))
    assert len(retained)==len(paths)
    followup=transactions.WorkspaceTransaction(root,sandbox.state_dir/'workspace-transactions',git_sandbox=sandbox)
    followup.close()


@pytest.mark.parametrize('stage',['refs_prepared','refs_commit_intent'])
def test_created_native_ref_preparation_supports_original_inode_rollback(tmp_path,monkeypatch,stage):
    from agentporter.sandbox import workspace_recovery as recovery
    root,sandbox,tx,guard,manager,history=unchanged_git_interruption(tmp_path,monkeypatch,native_stage=stage)
    plan=recovery.recover_workspace(sandbox.state_dir,root)
    inspected=plan['git'][0]['inspection']
    assert inspected['apply_supported'],inspected
    assert not inspected['before_endpoint_verified']
    result=recovery.recover_workspace(sandbox.state_dir,root,apply=True,restore_deletions=True,
        expected_plan_sha256=plan['plan_sha256'])
    assert result['status']=='recovered' and (root/'ordinary').read_text()=='initial'
    assert not tx._pending.exists() and not guard.exists()


def test_second_recovery_crash_after_native_index_capture_resumes(tmp_path,monkeypatch):
    from agentporter.sandbox import workspace_recovery as recovery,workspace_custody as custody
    from tests.security.custody.test_integration import assert_jobs
    root,sandbox,tx,guard,manager,history=unchanged_git_interruption(tmp_path,monkeypatch,native_stage='index_staged')
    child=os.fork()
    if child==0:
        original=custody._rename_noreplace
        def moved(source,name,destination,destname):
            result=original(source,name,destination,destname)
            if name.startswith('.agentporter-index-'):os._exit(73)
            return result
        custody._rename_noreplace=moved
        try:
            plan=recovery.recover_workspace(sandbox.state_dir,root)
            recovery.recover_workspace(sandbox.state_dir,root,apply=True,restore_deletions=True,
                                       expected_plan_sha256=plan['plan_sha256'])
        except BaseException:os._exit(74)
        os._exit(75)
    _,status=os.waitpid(child,0);assert os.waitstatus_to_exitcode(status)==73
    plan=recovery.recover_workspace(sandbox.state_dir,root)
    inspected=plan['git'][0]['inspection']
    assert inspected['apply_supported'],inspected
    assert any(item['path'].startswith('.agentporter-index-') and item['state']=='captured_expected'
               for item in inspected['metadata_custody'])
    result=recovery.recover_workspace(sandbox.state_dir,root,apply=True,restore_deletions=True,
                                      expected_plan_sha256=plan['plan_sha256'])
    assert result['status']=='recovered';assert_jobs(manager)
    raw.verify_git_baseline(root,history.raw_baseline_directory,history.raw_baseline['sha256'])


def test_equal_byte_owner_native_lock_substitution_blocks_recovery(tmp_path,monkeypatch):
    from agentporter.sandbox import workspace_recovery as recovery
    root,sandbox,tx,guard,manager,history=unchanged_git_interruption(tmp_path,monkeypatch,native_stage='index_staged')
    lock=root/'.git/index.lock';later=root/'.git/owner-lock'
    info=lock.stat();later.write_bytes(lock.read_bytes());later.chmod(stat.S_IMODE(info.st_mode))
    os.utime(later,ns=(info.st_atime_ns,info.st_mtime_ns));later.replace(lock);owner=lock.stat().st_ino
    worktree=(root/'ordinary').read_bytes()
    plan=recovery.recover_workspace(sandbox.state_dir,root)
    assert not plan['git'][0]['inspection']['apply_supported']
    with pytest.raises(PermissionError,match='coherent Git apply remains unsupported'):
        recovery.recover_workspace(sandbox.state_dir,root,apply=True,restore_deletions=True,expected_plan_sha256=plan['plan_sha256'])
    assert lock.stat().st_ino==owner and (root/'ordinary').read_bytes()==worktree


def test_late_index_fd_rebinding_cannot_bless_substituted_owner_inode(tmp_path,monkeypatch):
    from tests.security.custody.test_native_history import history,private_git
    from agentporter.sandbox import workspace_git as module
    root,item=history(tmp_path)
    try:
        (root/'ordinary').write_text('late index replacement fixture')
        private_git(item,'add','ordinary');private_git(item,'commit','-qm','late owner stage')
        item.prepare();item.guard_publication()
        original=(root/'.git/index').stat().st_ino
        marker="    publication_event('index_staged')"
        injection="""
    owned_info = os.stat(git_root + '/' + staged_index)
    with open(git_root + '/' + staged_index, 'rb') as owned_index:
        owner_bytes = owned_index.read()
    with open(git_root + '/.owner-stage', 'xb') as owner_file:
        owner_file.write(owner_bytes)
    os.chmod(git_root + '/.owner-stage', stat.S_IMODE(owned_info.st_mode))
    os.utime(git_root + '/.owner-stage', ns=(owned_info.st_atime_ns, owned_info.st_mtime_ns))
    os.replace(git_root + '/.owner-stage', git_root + '/' + staged_index)
    with open(git_root + '/.owner-stage-marker', 'x') as marker_file:
        marker_file.write(str(os.stat(git_root + '/' + staged_index).st_ino))
"""
        assert module._IMPORT.count(marker)==1
        monkeypatch.setattr(module,'_IMPORT',module._IMPORT.replace(marker,marker+injection))
        with pytest.raises(ResourceCleanupError):item.publish()
        owner=int((root/'.git/.owner-stage-marker').read_text())
        staged=list((root/'.git').glob('.agentporter-index-*'))
        assert len(staged)==1 and staged[0].stat().st_ino==owner
        assert (item.original_directory/'original-index/captured').stat().st_ino==original
        copy=json.loads((item.original_directory/'index-attempt-0000.json').read_text())
        assert (root/'.git/index').stat().st_ino==copy['signature'][1] and item.guard.exists()
        report=raw.inspect_native_git_phases(root,item.native_events,raw._digest(item.plan))
        assert any(event['stage']=='refs_committed' for event in report['events'])
        assert report['events'][-1]['bindings']['index']['record']['signature'][1]!=owner
    finally:item.close()


def test_unborn_repository_new_canonical_index_is_captured_back_to_absence(tmp_path,monkeypatch):
    from tests.security.custody.test_native_history import BubblewrapSandbox,RecordingResources
    from tests.security.custody.test_integration import stopped
    from agentporter.sandbox import workspace_git as module,workspace_recovery as recovery,workspace_transactions as transactions
    from agentporter.tools.jobs import JobManager
    root=tmp_path/'unborn';root.mkdir()
    subprocess.run(['/usr/bin/git','init','--quiet','--template=','-b','main',str(root)],check=True,capture_output=True)
    state=tmp_path/'state';state.mkdir(mode=0o700);JobManager(state)
    sandbox=BubblewrapSandbox(state,transactional_writes=True);sandbox.resources=RecordingResources()
    assert not (root/'.git/index').exists()
    marker="publication_event('index_published')"
    with monkeypatch.context() as patch:
        patch.setattr(module,'_IMPORT',module._IMPORT.replace(marker,marker+'; os._exit(73)'))
        with pytest.raises(ResourceCleanupError):
            sandbox.run(str(root),['/bin/sh','-c','printf "staged unborn index" > newfile && git add newfile'])
    tx=sandbox._unresolved_transactions[0];history=next(iter(tx.git_histories.values()));guard=history.guard
    assert (root/'.git/index').is_file()
    stopped(tx);monkeypatch.setattr(recovery,'_verify_stopped_service',lambda:None)
    plan=recovery.recover_workspace(state,root)
    inspected=plan['git'][0]['inspection']
    assert inspected['apply_supported'],inspected
    assert 'index' in {entry['path'] for entry in inspected['metadata_capture_plan']}
    result=recovery.recover_workspace(state,root,apply=True,restore_deletions=True,expected_plan_sha256=plan['plan_sha256'])
    assert result['status']=='recovered'
    assert not (root/'.git/index').exists() and not (root/'newfile').exists()
    assert not guard.exists() and not tx._pending.exists()
    raw.verify_git_baseline(root,history.raw_baseline_directory,history.raw_baseline['sha256'])
    followup=transactions.WorkspaceTransaction(root,state/'workspace-transactions',git_sandbox=sandbox)
    followup.close()


def test_successful_native_cleanup_captures_exact_guard_inodes(tmp_path):
    root,item=imported_history(tmp_path)
    try:
        native=raw.inspect_native_git_phases(root,item.native_events,raw._digest(item.plan))
        assert native['last_stage']=='cleanup_finished'
        assert {'index.lock','HEAD.lock'} <= native['events'][-1]['files'].keys()
        planned=json.loads((item.native_guard_directory/'cleanup-plan.json').read_text())
        assert (item.native_guard_directory/'done.json').is_file()
        done=json.loads((item.native_guard_directory/'done.json').read_text())
        returned=raw.inspect_git_phases(root,item.raw_baseline_directory)['events'][-1]
        assert returned['payload']['native_guard_cleanup_sha256']==done['cleanup_sha256']==raw._digest(planned)
        for entry in planned['entries']:
            captured=item.native_guard_directory/entry['slot']/'captured'
            assert captured.stat().st_ino==entry['expected']['signature'][1]
            assert not (root/'.git'/entry['path']).exists()
        item.finish()
    finally:item.close()


@pytest.mark.parametrize('name',['index.lock','HEAD.lock'])
def test_native_cleanup_preserves_equal_byte_owner_guard_substitution(tmp_path,monkeypatch,name):
    from tests.security.custody.test_native_history import history,private_git
    from agentporter.sandbox import workspace_git as module
    root,item=history(tmp_path)
    try:
        (root/'ordinary').write_text('native guard owner replacement')
        private_git(item,'add','ordinary');private_git(item,'commit','-qm','guard owner fixture')
        item.prepare();item.guard_publication()
        marker="    publication_event('cleanup_intent')"
        injected="""
    target = git_root + '/' + %r
    original_info = os.stat(target)
    with open(target, 'rb') as original_guard:
        owner_bytes = original_guard.read()
    with open(git_root + '/.owner-native-guard', 'xb') as owner_file:
        owner_file.write(owner_bytes)
    os.chmod(git_root + '/.owner-native-guard', stat.S_IMODE(original_info.st_mode))
    os.utime(git_root + '/.owner-native-guard', ns=(original_info.st_atime_ns, original_info.st_mtime_ns))
    os.replace(git_root + '/.owner-native-guard', target)
    with open(git_root + '/.owner-guard-marker', 'x') as marker_file:
        marker_file.write(str(os.stat(target).st_ino))
""" % name
        assert module._IMPORT.count(marker)==1
        monkeypatch.setattr(module,'_IMPORT',module._IMPORT.replace(marker,injected+marker))
        with pytest.raises(ResourceCleanupError,match='Native guard retirement'):item.publish()
        owner=int((root/'.git/.owner-guard-marker').read_text())
        assert (root/'.git'/name).stat().st_ino==owner
        assert item.guard.exists() and not (item.native_guard_directory/'done.json').exists()
        assert raw.inspect_git_phases(root,item.raw_baseline_directory)['events'][-1]['phase']=='import_started'
    finally:item.close()


def test_host_native_guard_capture_crash_retries_without_reexecuting_git(tmp_path):
    from tests.security.custody.test_native_history import history,private_git
    from agentporter.sandbox import workspace_custody as custody,native_git_cleanup
    root,item=history(tmp_path)
    try:
        (root/'ordinary').write_text('host guard capture interruption')
        private_git(item,'add','ordinary');private_git(item,'commit','-qm','host capture fixture')
        item.prepare();item.guard_publication()
        child=os.fork()
        if child==0:
            original=custody._rename_noreplace
            def die(source,name,destination,destname):
                result=original(source,name,destination,destname)
                if name=='index.lock':os._exit(73)
                return result
            custody._rename_noreplace=die
            try:item.publish()
            except BaseException:os._exit(74)
            os._exit(75)
        _,status=os.waitpid(child,0);assert os.waitstatus_to_exitcode(status)==73
        native=raw.inspect_native_git_phases(root,item.native_events,raw._digest(item.plan))
        assert native['last_stage']=='cleanup_finished'
        first=native_git_cleanup.retire(root,item.native_guard_directory,item.plan,native)
        assert native_git_cleanup.retire(root,item.native_guard_directory,item.plan,native)==first
        assert not (root/'.git/index.lock').exists() and not (root/'.git/HEAD.lock').exists()
        assert item.guard.exists()
        with pytest.raises(ResourceCleanupError,match='prior uncertain lifecycle'):item.publish()
    finally:item.close()


def test_owner_guard_swap_at_atomic_host_capture_is_restored(tmp_path,monkeypatch):
    from tests.security.custody.test_native_history import history,private_git
    from agentporter.sandbox import workspace_custody as custody
    root,item=history(tmp_path);owner=[]
    original=custody._rename_noreplace
    def race(source,name,destination,destname):
        if name=='index.lock' and not owner:
            target=root/'.git/index.lock';info=target.stat()
            later=root/'.git/owner-native-lock';later.write_bytes(target.read_bytes())
            later.chmod(stat.S_IMODE(info.st_mode));os.utime(later,ns=(info.st_atime_ns,info.st_mtime_ns))
            later.replace(target);owner.append(target.stat().st_ino)
        return original(source,name,destination,destname)
    monkeypatch.setattr(custody,'_rename_noreplace',race)
    try:
        (root/'ordinary').write_text('atomic host cleanup race')
        private_git(item,'add','ordinary');private_git(item,'commit','-qm','atomic cleanup')
        item.prepare();item.guard_publication()
        with pytest.raises(ResourceCleanupError,match='Native guard retirement'):item.publish()
        assert owner and (root/'.git/index.lock').stat().st_ino==owner[0]
        assert item.guard.exists() and not (item.native_guard_directory/'done.json').exists()
    finally:item.close()


def test_native_guard_mount_preflight_refuses_before_worktree_publication(tmp_path,monkeypatch):
    from tests.security.custody.test_native_history import setup,BubblewrapSandbox,RecordingResources,git
    from agentporter.sandbox import workspace_custody as custody
    root,_,initial=setup(tmp_path);old=git(root,'rev-parse','HEAD')
    sandbox=BubblewrapSandbox(initial.state_dir,transactional_writes=True);sandbox.resources=RecordingResources()
    original=custody._mount_id
    def different(fd):
        return original(fd)+(1 if '/native-guard-retire/' in os.readlink('/proc/self/fd/'+str(fd)) else 0)
    monkeypatch.setattr(custody,'_mount_id',different)
    result=sandbox.run(str(root),['/bin/sh','-c',
        'printf "private edit must not publish" > ordinary && git add ordinary && git commit -qm "preflight refusal"'])
    assert result['exit_code']!=0
    assert (root/'ordinary').read_text()=='initial' and git(root,'rev-parse','HEAD')==old
    assert not list((sandbox.state_dir/'workspace-transactions').glob('*.pending.json'))
    assert not list((sandbox.state_dir/'workspace-transactions').glob('*.git-pending.json'))


def test_native_import_retains_exact_original_index_head_and_index_flags(tmp_path):
    from tests.security.custody.test_native_history import setup,BubblewrapSandbox,RecordingResources,private_git
    from agentporter.sandbox.workspace_git import WorkspaceGitHistory
    root,_,initial=setup(tmp_path)
    subprocess.run(['/usr/bin/git','-C',str(root),'update-index','--assume-unchanged','ordinary'],check=True,capture_output=True)
    (root/'.git/index').chmod(0o640);os.setxattr(root/'.git/index','user.original',b'index metadata')
    original={name:(root/'.git'/name).stat().st_ino for name in ('index','HEAD')}
    sandbox=BubblewrapSandbox(initial.state_dir,transactional_writes=True);sandbox.resources=RecordingResources()
    (sandbox.state_dir/'workspace-transactions').mkdir(exist_ok=True)
    item=WorkspaceGitHistory(root,tmp_path/'native-original-history',sandbox)
    try:
        private_git(item,'update-index','--no-assume-unchanged','ordinary')
        (root/'ordinary').write_text('native changes retain original flags')
        private_git(item,'add','ordinary');private_git(item,'commit','-qm','retained original fixture')
        item.prepare();item.guard_publication();item.publish()
        for path,inode in original.items():
            assert (item.original_directory/('original-'+path)/'captured').stat().st_ino==inode
        index=item.original_directory/'original-index/captured'
        flags=subprocess.check_output(['/usr/bin/git','-c','core.fsmonitor=false','-C',str(root),'ls-files','-v'],
            env={**os.environ,'GIT_INDEX_FILE':str(index),'GIT_OPTIONAL_LOCKS':'0'}).decode()
        assert flags.strip()=='h ordinary'
        assert stat.S_IMODE(index.stat().st_mode)==0o640 and os.getxattr(index,'user.original')==b'index metadata'
        item.finish()
    finally:item.close()


@pytest.mark.parametrize('stage',['before_original_capture','after_original_capture','before_copy_linked','after_head_capture','head_copy_linked'])
def test_integrated_original_preservation_crash_recovers_exact_before(tmp_path,monkeypatch,stage):
    from tests.security.custody.test_native_history import setup,BubblewrapSandbox,RecordingResources
    from agentporter.sandbox import workspace_recovery as recovery,git_original_metadata as originals,workspace_custody as custody,workspace_delta as delta
    from agentporter.tools.jobs import JobManager
    from agentporter.workspaces.leases import workspace_key
    root,_,initial=setup(tmp_path);initial.state_dir.chmod(0o700)
    original={name:(root/'.git'/name).stat().st_ino for name in ('index','HEAD')}
    manager=JobManager(initial.state_dir)
    sandbox=BubblewrapSandbox(initial.state_dir,transactional_writes=True);sandbox.resources=RecordingResources()
    from tests.security.custody.authorization_seams import allow_one_history_publication_for_recovery
    allow_one_history_publication_for_recovery(monkeypatch,root)
    child=os.fork()
    if child==0:
        write=originals._write
        def prepared(directory,name,data):
            result=write(directory,name,data)
            if stage=='before_original_capture' and name.startswith('index-attempt-'):os._exit(73)
            return result
        originals._write=prepared
        rename=custody._rename_noreplace
        def captured(source,name,destination,destname):
            result=rename(source,name,destination,destname)
            if stage=='after_original_capture' and name=='index':os._exit(73)
            if stage=='after_head_capture' and name=='HEAD':os._exit(73)
            return result
        custody._rename_noreplace=captured
        link=delta._publish_restore_fd
        def linked(parent,source,name):
            result=link(parent,source,name)
            if stage=='before_copy_linked' and name=='index':os._exit(73)
            if stage=='head_copy_linked' and name=='HEAD':os._exit(73)
            return result
        delta._publish_restore_fd=linked
        try:sandbox.run(str(root),['/bin/sh','-c','printf "interrupted original preservation" > ordinary && git add ordinary && git commit -qm "original phase"'])
        except BaseException:os._exit(74)
        os._exit(75)
    _,status=os.waitpid(child,0);assert os.waitstatus_to_exitcode(status)==73
    journal=sandbox.state_dir/'workspace-transactions'/(workspace_key(root.stat())+'.pending.json')
    data=json.loads(journal.read_text());directory=Path(data['transaction'])
    connection=manager._get_db()
    with connection:
        connection.execute("INSERT INTO jobs(job_id,workspace_id,status,argv,created_at,workspace_transaction) VALUES ('owned','fixture','cleanup_failed','[]',0,?)",(str(directory),))
        connection.execute("INSERT INTO job_admissions VALUES ('own','owned',0,0)")
    connection.close()
    monkeypatch.setattr(recovery,'_verify_stopped_service',lambda:None)
    plan=recovery.recover_workspace(sandbox.state_dir,root)
    assert plan['git'][0]['inspection']['apply_supported'],plan
    result=recovery.recover_workspace(sandbox.state_dir,root,apply=True,restore_deletions=True,expected_plan_sha256=plan['plan_sha256'])
    assert result['status']=='recovered' and (root/'ordinary').read_text()=='initial'
    for name,inode in original.items():assert (root/'.git'/name).stat().st_ino==inode
    assert not journal.exists()
    connection=manager._get_db()
    try:
        assert connection.execute("SELECT status FROM jobs WHERE job_id='owned'").fetchone()[0]=='recovered'
        assert not connection.execute("SELECT 1 FROM job_admissions WHERE token='own'").fetchone()
    finally:connection.close()


def test_native_replaced_index_head_can_return_exact_retained_originals(tmp_path):
    from agentporter.sandbox import git_original_metadata as originals
    root,item=imported_history(tmp_path)
    try:
        native=raw.inspect_native_git_phases(root,item.native_events,raw._digest(item.plan))
        for path in ('index','HEAD'):
            original=item.raw_baseline['manifest']['files'][path]
            proof=native['events'][-1]['bindings'][path]['record']
            assert (root/'.git'/path).stat().st_ino!=original['identity'][1]
            originals.restore_original(root,item.original_directory,path,proven_after=proof)
            assert (root/'.git'/path).stat().st_ino==original['identity'][1]
            assert (item.original_directory/('displaced-'+path)/'captured').is_file()
        # This exercises file restoration only: refs/worktree are not undone,
        # and no guard/job/admission is retired by this component.
        assert item.guard.exists()
    finally:item.close()
