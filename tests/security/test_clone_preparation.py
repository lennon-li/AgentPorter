import hashlib,json,subprocess
from tests.security.test_development_runtime import runtime_factory
from pathlib import Path
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from agentporter.git_approvals import GitApprovalVerifier,issue_git_approval
from agentporter.git_smart_http import Advertisement
from agentporter.git_clone_preparation import CloneScope,prepare_clone as prepare_clone_impl
from tests.security.custody.test_repository_birth import fixture,metadata,git


def context(tx):
    info=tx.directory.stat()
    return {'job_id':'job_'+'a'*24,'agent':'codex_research','admission_token':'b'*32,
        'transaction_directory':str(tx.directory),'transaction_device':info.st_dev,'transaction_inode':info.st_ino}


def prepare_clone(tx,sandbox,scope,broker):
    return prepare_clone_impl(tx,sandbox,scope,broker,job_context=context(tx))


def source_pack(tmp_path,kind):
    source=tmp_path/'remote';source.mkdir()
    git(source,'init','-q','--object-format='+kind,'--initial-branch=main','--template=')
    git(source,'config','user.name','Remote');git(source,'config','user.email','remote@example.invalid')
    (source/'remote-file').write_text('remote approved fixture\n');git(source,'add','remote-file');git(source,'commit','-qm','remote seed')
    oid=git(source,'rev-parse','HEAD')
    pack=subprocess.run(['/usr/bin/git','pack-objects','--stdout','--revs'],cwd=source,
        input=(oid+'\n').encode(),capture_output=True,check=True).stdout
    class Broker:
        def discover(self,service):assert service=='git-upload-pack';return Advertisement({'refs/heads/main':oid},frozenset(),kind)
        def fetch_pack(self,ref,expected):assert (ref,expected)==('refs/heads/main',oid);return pack
    return oid,pack,Broker()


@pytest.mark.parametrize('kind',['sha1','sha256'])
@pytest.mark.parametrize('outer_git',[True,False])
def test_private_clone_prepares_parent_bound_request_without_canonical_write(tmp_path,kind,outer_git):
    root,state,sandbox,tx=fixture(tmp_path,outer_git)
    before=metadata(root);oid,pack,broker=source_pack(tmp_path,kind)
    scope=CloneScope('fixture',str(root),'new-clone','origin','https://example.com/owner/repo.git','refs/heads/main','refs/heads/main','a'*64)
    try:
        request,candidate=prepare_clone(tx,sandbox,scope,broker)
        assert not (root/'new-clone').exists() and metadata(root)==before
        assert (candidate/'remote-file').read_text()=='remote approved fixture\n'
        assert git(candidate,'rev-parse','HEAD')==oid
        payload=request.to_payload();assert payload['operation']=='clone' and payload['repository_path']==str(root)
        assert payload['repository_inode']==root.stat().st_ino and payload['expected_head']is None
        assert payload['parameters']['identity_kind']=='parent_workspace'
        assert payload['parameters']['pack_sha256']==hashlib.sha256(pack).hexdigest()
        assert payload['parameters']['target_before']['kind']=='absent'
        assert payload['parameters']['private_candidate']['inode']==candidate.stat().st_ino
        key=Ed25519PrivateKey.generate();verifier=GitApprovalVerifier(key.public_key(),tmp_path/'claims/claims.db')
        receipt=issue_git_approval(key,request);verifier.verify_and_consume(receipt,request)
        with pytest.raises(PermissionError):verifier.verify_and_consume(receipt,request)
    finally:tx.close()


def test_private_clone_accepts_only_original_empty_target(tmp_path):
    root,state,sandbox,tx=fixture(tmp_path,False,existing=True);oid,pack,broker=source_pack(tmp_path,'sha1')
    scope=CloneScope('fixture',str(root),'existing','origin','https://example.com/owner/repo.git','refs/heads/main','refs/heads/main','a'*64)
    original=(root/'existing').stat().st_ino
    try:
        request,candidate=prepare_clone(tx,sandbox,scope,broker)
        assert request.to_payload()['parameters']['target_before']['kind']=='empty'
        assert (root/'existing').stat().st_ino==original and not list((root/'existing').iterdir())
    finally:tx.close()


def test_clone_rejects_target_drift_during_acquisition(tmp_path):
    root,state,sandbox,tx=fixture(tmp_path,False);oid,pack,broker=source_pack(tmp_path,'sha1')
    scope=CloneScope('fixture',str(root),'new-clone','origin','https://example.com/owner/repo.git','refs/heads/main','refs/heads/main','a'*64)
    original=broker.fetch_pack
    def mutate(ref,expected):
        (root/'new-clone').mkdir();(root/'new-clone/owner').write_text('owner')
        return original(ref,expected)
    broker.fetch_pack=mutate
    try:
        with pytest.raises(PermissionError):prepare_clone(tx,sandbox,scope,broker)
        assert (root/'new-clone/owner').read_text()=='owner'
    finally:tx.close()


@pytest.mark.parametrize('repository',['.','../outside','child/../outside','/outside','.git/escape','repo//child'])
def test_clone_scope_rejects_unqualified_or_escaped_target(repository):
    with pytest.raises((ValueError,PermissionError)):
        CloneScope('fixture','/workspace',repository,'origin','https://example.com/owner/repo.git','refs/heads/main','refs/heads/main','a'*64)


@pytest.mark.parametrize('change',['job','agent','token','directory','inode','extra'])
def test_clone_proposal_refuses_malformed_service_context(tmp_path,change):
    root,state,sandbox,tx=fixture(tmp_path,False);oid,pack,broker=source_pack(tmp_path,'sha1')
    scope=CloneScope('fixture',str(root),'new-clone','origin','https://example.com/owner/repo.git','refs/heads/main','refs/heads/main','a'*64)
    ctx=context(tx)
    if change=='job':ctx['job_id']='other'
    elif change=='agent':ctx['agent']='other'
    elif change=='token':ctx['admission_token']='other'
    elif change=='directory':ctx['transaction_directory']='/other'
    elif change=='inode':ctx['transaction_inode']+=1
    else:ctx['verification_key']='attacker'
    try:
        with pytest.raises(PermissionError):prepare_clone_impl(tx,sandbox,scope,broker,job_context=ctx)
        assert not (root/'new-clone').exists()
    finally:tx.close()


@pytest.mark.parametrize('change',['checksum','noncommit','missinggraph'])
def test_clone_quarantine_rejects_invalid_or_incomplete_graph_without_canonical_write(tmp_path,change):
    root,state,sandbox,tx=fixture(tmp_path,False);oid,pack,broker=source_pack(tmp_path,'sha1')
    scope=CloneScope('fixture',str(root),'new-clone','origin','https://example.com/owner/repo.git','refs/heads/main','refs/heads/main','a'*64)
    if change=='checksum':bad=pack[:-1]+bytes([pack[-1]^1])
    elif change=='missinggraph':
        bad=subprocess.run(['/usr/bin/git','pack-objects','--stdout'],cwd=tmp_path/'remote',input=(oid+'\n').encode(),capture_output=True,check=True).stdout
    else:
        oid=git(tmp_path/'remote','rev-parse','HEAD^{tree}');bad=pack
    broker.discover=lambda service:Advertisement({'refs/heads/main':oid},frozenset(),'sha1')
    broker.fetch_pack=lambda ref,expected:bad
    try:
        with pytest.raises((PermissionError,ValueError)):prepare_clone(tx,sandbox,scope,broker)
        assert not (root/'new-clone').exists()
    finally:tx.close()


def test_clone_keeps_existing_parent_lease_and_every_phase_is_offline(tmp_path,monkeypatch):
    from agentporter.sandbox.workspace_transactions import WorkspaceTransaction
    root,state,sandbox,tx=fixture(tmp_path,False);oid,pack,broker=source_pack(tmp_path,'sha1')
    scope=CloneScope('fixture',str(root),'new-clone','origin','https://example.com/owner/repo.git','refs/heads/main','refs/heads/main','a'*64)
    original_fetch=broker.fetch_pack
    def fetched(ref,expected):
        with pytest.raises(PermissionError,match='active transaction'):
            WorkspaceTransaction(root,state/'workspace-transactions',git_sandbox=sandbox)
        return original_fetch(ref,expected)
    broker.fetch_pack=fetched
    original=sandbox._run_command;calls=[]
    def checked(**options):calls.append(options);return original(**options)
    monkeypatch.setattr(sandbox,'_run_command',checked)
    try:
        request,candidate=prepare_clone(tx,sandbox,scope,broker)
        assert calls and all(row['network_access']is False for row in calls)
        assert request.to_payload()['parameters']['job_context']['transaction_inode']==tx.directory.stat().st_ino
        assert tx._closed is False and not (root/'new-clone').exists()
    finally:tx.close()

@pytest.mark.parametrize('outer_git',[True,False])
@pytest.mark.parametrize('authority',['missing','untyped','no_runtime'])
def test_clone_materialization_without_owned_runtime_and_typed_authority_refuses_before_claim(tmp_path,monkeypatch,outer_git,authority):
    import sqlite3
    from agentporter.git_clone_preparation import consume_clone
    from agentporter.git_clone_authority import CloneBirthAuthorization
    root,state,sandbox,tx=fixture(tmp_path,outer_git);before=metadata(root)
    canonical_before={path.relative_to(root).as_posix():(path.stat().st_ino,path.stat().st_mode,path.read_bytes()) for path in root.rglob('*') if path.is_file()}
    oid,pack,broker=source_pack(tmp_path,'sha1')
    scope=CloneScope('fixture',str(root),'new-clone','origin','https://example.com/owner/repo.git','refs/heads/main','refs/heads/main','a'*64)
    key=Ed25519PrivateKey.generate();verifier=GitApprovalVerifier(key.public_key(),tmp_path/'claims/claims.db')
    try:
        request,candidate=prepare_clone(tx,sandbox,scope,broker);receipt=issue_git_approval(key,request)
        assert tx._runtime_view_fd is None and tx._runtime_namespace_fds is None
        cap=None if authority=='missing' else object() if authority=='untyped' else CloneBirthAuthorization(None,tx,b'{}')
        def no_execution(**options):raise AssertionError('Unadmitted clone reached materialization helper')
        monkeypatch.setattr(sandbox,'_run_command',no_execution)
        with pytest.raises(PermissionError,match='typed owner birth authority|verified live transaction'):
            consume_clone(tx,sandbox,scope,request,candidate,receipt,verifier,job_context=context(tx),birth_authorization=cap)
        with sqlite3.connect('file:'+str(verifier.ledger_path)+'?mode=ro',uri=True) as ledger:
            assert ledger.execute('SELECT count(*) FROM consumed').fetchone()==(0,)
        assert not (root/'new-clone').exists() and metadata(root)==before
        assert not (tx.upper/'new-clone').exists()
        assert {path.relative_to(root).as_posix():(path.stat().st_ino,path.stat().st_mode,path.read_bytes()) for path in root.rglob('*') if path.is_file()}==canonical_before
        # This independently valid synthetic receipt remains unspent.
        verifier.verify_and_consume(receipt,request)
    finally:tx.close()


@pytest.mark.parametrize('outer_git',[True,False])
def test_authoritative_job_missing_runtime_view_does_not_consume_owner_receipt(tmp_path,monkeypatch,runtime_factory,outer_git):
    import sqlite3
    from tests.security.test_clone_service import setup_clone
    root,service,key,manager,tx,bound,request=setup_clone(tmp_path,monkeypatch,runtime_factory,outer_git=outer_git)
    receipt=issue_git_approval(key,request)
    canonical_before={path.relative_to(root).as_posix():(path.stat().st_ino,path.stat().st_mode,path.read_bytes()) for path in root.rglob('*') if path.is_file()}
    view=tx._runtime_view_fd
    assert view is not None
    tx._runtime_view_fd=None
    def no_execution(**options):raise AssertionError('Missing trusted view reached clone materialization')
    monkeypatch.setattr(service.sandbox,'_run_command',no_execution)
    try:
        with pytest.raises(PermissionError,match='before approval consumption'):
            bound.execute(request.digest,receipt)
        with sqlite3.connect('file:'+str(bound.backend.verifier.ledger_path)+'?mode=ro',uri=True) as ledger:
            assert ledger.execute('SELECT count(*) FROM consumed').fetchone()==(0,)
        assert not (root/'new-clone').exists() and not (tx.upper/'new-clone').exists()
        assert {path.relative_to(root).as_posix():(path.stat().st_ino,path.stat().st_mode,path.read_bytes()) for path in root.rglob('*') if path.is_file()}==canonical_before
        assert not getattr(tx,'_private_clone_pending',False)
        db=manager._get_db()
        try:
            assert db.execute('SELECT count(*) FROM job_admissions WHERE job_id=?',(bound.job_id,)).fetchone()[0]==1
            assert db.execute('SELECT status FROM git_admissions').fetchone()[0]=='resolved'
        finally:db.close()
    finally:
        tx._runtime_view_fd=view
        manager.cancel(bound.job_id)
