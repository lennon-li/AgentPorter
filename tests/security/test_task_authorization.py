import time

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from agentporter.scoped_approvals import ApprovalVerifier, sign_grant
from agentporter.task_authorization import TaskAuthorization, ACTIVE_GRANT
from agentporter.agents.production_relay import normalize_dispatch
from agentporter.workspaces.registry import WorkspaceRegistry


@pytest.fixture
def authority(tmp_path):
    root=tmp_path/'workspace';root.mkdir()
    registry=WorkspaceRegistry({'project':{'path':str(root),'allow_agent_dispatch':True}})
    key=Ed25519PrivateKey.generate();state=tmp_path/'approvals';state.mkdir(mode=0o700)
    verifier=ApprovalVerifier(key.public_key(),state/'ledger.db')
    return TaskAuthorization(registry,verifier),key,root


def arguments():
    return normalize_dispatch({'workspace_id':'project','agent':'jax','task':'Make a scoped edit','read_only':False})


def test_read_only_delegation_needs_no_approval(authority):
    auth,_,_=authority
    with auth.authorize('dispatch_agent',{'workspace_id':'project','agent':'jax','task':'Read only'}):
        assert ACTIVE_GRANT.get() is None


@pytest.mark.parametrize('action', ['list_files', 'dispatch_agent', 'exec_run'])
def test_unknown_shared_workspace_is_a_permission_denial(authority, action):
    auth, _, _ = authority
    auth.registry.workspace_policy = object()
    with pytest.raises(PermissionError, match='Workspace outside authorized scope'):
        with auth.authorize(action, {'workspace_id': 'NOT_REGISTERED'}):
            pytest.fail('Unknown workspace reached tool execution')


def test_writable_missing_approval_is_denied(authority):
    auth,_,_=authority
    with pytest.raises((ValueError,PermissionError)):
        with auth.authorize('dispatch_agent',arguments()):pass


def test_exact_writable_task_is_authorized_once_for_retries(authority):
    auth,key,root=authority;args=arguments()
    token=sign_grant(key,workspace_id='project',workspace_root=str(root),action='dispatch_agent',
                     arguments=args,agent='jax',operations=['write'],expires_at=int(time.time())+60)
    args.update(approval_token=token,request_id='a'*32)
    for _ in range(2):
        with auth.authorize('dispatch_agent',args):
            assert ACTIVE_GRANT.get().claims['workspace_root']==str(root)
    assert ACTIVE_GRANT.get() is None


def test_grant_cannot_be_reused_for_changed_task(authority):
    auth,key,root=authority;args=arguments()
    token=sign_grant(key,workspace_id='project',workspace_root=str(root),action='dispatch_agent',
                     arguments=args,agent='jax',operations=['write'],expires_at=int(time.time())+60)
    args.update(approval_token=token,request_id='a'*32,task='Different task')
    with pytest.raises(PermissionError):
        with auth.authorize('dispatch_agent',args):pass


def test_destructive_tool_requires_separate_operation_grant(authority):
    auth,_,_=authority
    with pytest.raises((ValueError,PermissionError)):
        with auth.authorize('trash_path',{'workspace_id':'project','path':'code.py'}):pass


def test_plain_edits_allowed_by_workspace_default(authority):
    auth,_,_=authority
    with auth.authorize('write_file',{'workspace_id':'project','path':'code.py','content':'x'}):
        assert ACTIVE_GRANT.get() is None


def test_shared_rest_mcp_wrapper_checks_grant_before_tool(authority):
    from agentporter.server import _monitored_tool
    auth,_,_=authority
    called=[]
    wrapped=_monitored_tool('dispatch_agent',authorization=auth)(lambda **kw:called.append(kw))
    with pytest.raises((ValueError,PermissionError)):wrapped(**arguments())
    assert not called


def test_audit_does_not_log_approval_token(caplog):
    import logging
    from agentporter.server import log_tool_event
    caplog.set_level(logging.INFO)
    log_tool_event('dispatch_agent',{'workspace_id':'project','approval_token':'secret-grant-token'}, {},.1)
    assert 'secret-grant-token' not in caplog.text
