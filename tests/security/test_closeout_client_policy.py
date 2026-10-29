import json

import pytest
import yaml
from starlette.testclient import TestClient
from agentporter.server import create_asgi_app
from agentporter.client_policy import PublicClientPolicy


@pytest.fixture
def scoped_config(temp_config,tmp_path):
    temp_config.security.allowed_hosts=['testserver']
    for name in ('allowed','obsidian'):
        root = tmp_path/name;root.mkdir();(root/'fixture.txt').write_text(name)
        temp_config.workspaces[name]={'path':str(root),'writable':True,'allow_execute':True,'allow_agent_dispatch':True}
    path=temp_config.config_dir/'public-client-policy.yaml'
    path.write_text(yaml.safe_dump({'version':1,'workspaces':{
        'allowed':{'path':str(tmp_path/'allowed'),'operations':['read']}}}))
    path.chmod(0o600)
    key=temp_config.config_dir/'internal-client.key';key.write_text('synthetic-internal-client-key-32-bytes');key.chmod(0o600)
    return temp_config


def rpc(client,key,name,args):
    response=client.post('/mcp',headers={'X-AgentPorter-Key':key,'Accept':'application/json, text/event-stream'},
        json={'jsonrpc':'2.0','id':1,'method':'tools/call','params':{'name':name,'arguments':args}})
    assert response.status_code==200,response.text
    if response.headers.get('content-type','').startswith('text/event-stream'):
        return json.loads(next(line[6:] for line in response.text.splitlines() if line.startswith('data: ')))
    return response.json()


def test_actual_mcp_public_scopes_cannot_be_bypassed_by_local_source_or_key_switch(scoped_config):
    with TestClient(create_asgi_app(scoped_config), client=('127.0.0.1',12345)) as client:
        key=scoped_config.api_key
        result=rpc(client,key,'read_file',{'workspace_id':'allowed','path':'fixture.txt'})
        assert not result['result'].get('isError'),result
        for name,args in [('read_file',{'workspace_id':'obsidian','path':'fixture.txt'}),
            ('write_file',{'workspace_id':'allowed','path':'bad','content':'bad'}),
            ('exec_run',{'workspace_id':'allowed','argv':['true']}),
            ('read_file',{'workspace_id':'allowed','path':'../obsidian/fixture.txt'})]:
            assert rpc(client,key,name,args)['result']['isError']
        assert not rpc(client,'synthetic-internal-client-key-32-bytes','read_file',
            {'workspace_id':'obsidian','path':'fixture.txt'})['result'].get('isError')
        assert rpc(client,key,'read_file',{'workspace_id':'obsidian','path':'fixture.txt'})['result']['isError']
        fetch_args = {'workspace_id':'allowed','branch':'refs/heads/reviewed','prepare_only':True}
        assert rpc(client,key,'git_fetch',fetch_args)['result']['isError']
        assert client.post('/api/v1/workspaces/allowed/git/fetch',
            json={'branch':'refs/heads/reviewed','prepare_only':True},
            headers={'X-AgentPorter-Key':key}).status_code == 403


def test_internal_key_requires_direct_local_transport(scoped_config):
    with TestClient(create_asgi_app(scoped_config)) as client:
        response=client.get('/api/v1/server/deploy-info',headers={
            'X-AgentPorter-Key':'synthetic-internal-client-key-32-bytes','X-Forwarded-For':'127.0.0.1'})
        assert response.status_code==401


def test_git_fetch_requires_its_own_public_scope(scoped_config, tmp_path):
    from agentporter.client_policy import PRINCIPAL
    from agentporter.workspaces.registry import WorkspaceRegistry
    policy_path = scoped_config.config_dir / 'public-client-policy.yaml'
    original = yaml.safe_load(policy_path.read_text())
    original['workspaces']['allowed']['operations'] = ['read', 'git_read']
    policy_path.write_text(yaml.safe_dump(original))
    policy_path.chmod(0o600)
    registry = WorkspaceRegistry(scoped_config.workspaces)
    token = PRINCIPAL.set('public')
    try:
        policy = PublicClientPolicy(scoped_config.config_dir, scoped_config.state_dir, registry)
        with pytest.raises(PermissionError, match='outside public-client scope'):
            policy.check('git_fetch', {'workspace_id': 'allowed'})
        original['workspaces']['allowed']['operations'].append('git_fetch')
        policy_path.write_text(yaml.safe_dump(original))
        policy_path.chmod(0o600)
        expanded = PublicClientPolicy(scoped_config.config_dir, scoped_config.state_dir, registry)
        assert expanded.check('git_fetch', {'workspace_id': 'allowed'}) is None
    finally:
        PRINCIPAL.reset(token)


def test_rest_scopes_and_internal_workflow(scoped_config,tmp_path):
    with TestClient(create_asgi_app(scoped_config),client=('127.0.0.1',12345)) as client:
        public={'X-AgentPorter-Key':scoped_config.api_key}
        internal={'X-AgentPorter-Key':'synthetic-internal-client-key-32-bytes'}
        prefix='/api/v1/workspaces/'
        assert client.post(prefix+'allowed/files/read',json={'path':'fixture.txt'},headers=public).status_code==200
        assert client.post(prefix+'obsidian/files/read',json={'path':'fixture.txt'},headers=public).status_code==403
        assert client.post(prefix+'allowed/files/write',json={'path':'new','content':'bad'},headers=public).status_code==403
        assert client.post(prefix+'obsidian/files/write',json={'path':'new','content':'internal'},headers=internal).status_code==200
        assert (tmp_path/'obsidian/new').read_text()=='internal'
        rows=client.get(prefix,headers=public).json()
        assert [r['workspace_id'] for r in rows]==['allowed']
        (tmp_path/'allowed/alias').symlink_to(tmp_path/'obsidian/fixture.txt')
        # Existing path validation also rejects aliases into another workspace.
        response=rpc(client,scoped_config.api_key,'read_file',{'workspace_id':'allowed','path':'alias'})
        assert response['result']['isError']
        assert client.post(prefix+'allowed/files/read',json={'path':'fixture.txt'},headers={'X-AgentPorter-Key':'wrong'}).status_code==401


def test_missing_required_public_policy_fails_closed(temp_config):
    from agentporter.workspaces.registry import WorkspaceRegistry
    with pytest.raises(PermissionError,match='absent'):
        PublicClientPolicy(temp_config.config_dir,temp_config.state_dir,WorkspaceRegistry(),required=True)


def test_public_job_ownership_is_durable_and_connections_close(scoped_config,monkeypatch):
    import sqlite3
    from agentporter.client_policy import PRINCIPAL
    from agentporter.workspaces.registry import WorkspaceRegistry
    real_connect=sqlite3.connect
    opened=[];closed=[]
    class TrackingConnection(sqlite3.Connection):
        def close(self):
            closed.append(id(self));super().close()
    def connect(*args,**kwargs):
        connection=real_connect(*args,**kwargs,factory=TrackingConnection)
        opened.append(id(connection));return connection
    monkeypatch.setattr(sqlite3,'connect',connect)
    registry=WorkspaceRegistry(scoped_config.workspaces)
    policy=PublicClientPolicy(scoped_config.config_dir,scoped_config.state_dir,registry)
    token=PRINCIPAL.set('public')
    try:
        with pytest.raises(PermissionError,match='ownership'):
            policy.check('job_result',{'job_id':'unrelated'})
        policy.result('dispatch_agent',{'workspace_id':'allowed'},{'job_id':'owned'})
        restarted=PublicClientPolicy(scoped_config.config_dir,scoped_config.state_dir,registry)
        for _ in range(30):restarted.check('job_result',{'job_id':'owned'})
        with pytest.raises(PermissionError):restarted.check('unmapped_operation',{'workspace_id':'allowed'})
    finally:PRINCIPAL.reset(token)
    assert opened and opened==closed


def test_public_cancel_requires_owned_job_and_retained_launch_scope(scoped_config):
    from agentporter.client_policy import PRINCIPAL
    from agentporter.workspaces.registry import WorkspaceRegistry
    policy=PublicClientPolicy(scoped_config.config_dir,scoped_config.state_dir,WorkspaceRegistry(scoped_config.workspaces))
    token=PRINCIPAL.set('public')
    try:
        policy.result('exec_start',{'workspace_id':'allowed'},{'job_id':'owned'})
        with pytest.raises(PermissionError,match='retained'):
            policy.check('job_cancel',{'job_id':'owned'})
        policy.scopes['allowed']=frozenset({'read','exec'})
        policy.check('job_cancel',{'job_id':'owned'})
        with pytest.raises(PermissionError,match='ownership'):
            policy.check('job_cancel',{'job_id':'unrelated','workspace_id':'allowed'})
        policy.scopes={}
        with pytest.raises(PermissionError,match='ownership'):
            policy.check('job_cancel',{'job_id':'owned'})
    finally:PRINCIPAL.reset(token)


def test_real_mcp_and_rest_cancel_share_public_ownership_gate(scoped_config,monkeypatch):
    from agentporter.client_policy import PRINCIPAL
    from agentporter.workspaces.registry import WorkspaceRegistry
    from agentporter.tools.jobs import JobManager
    path=scoped_config.config_dir/'public-client-policy.yaml'
    document=yaml.safe_load(path.read_text())
    document['workspaces']['allowed']['operations']=['read','exec']
    path.write_text(yaml.safe_dump(document))
    policy=PublicClientPolicy(scoped_config.config_dir,scoped_config.state_dir,WorkspaceRegistry(scoped_config.workspaces))
    token=PRINCIPAL.set('public')
    try:policy.result('exec_start',{'workspace_id':'allowed'},{'job_id':'owned'})
    finally:PRINCIPAL.reset(token)
    seen=[]
    def cancel(self,job_id):
        seen.append(job_id)
        return {'job_id':job_id,'status':'cancelled','message':'synthetic owned process'}
    monkeypatch.setattr(JobManager,'cancel',cancel)
    with TestClient(create_asgi_app(scoped_config),client=('127.0.0.1',12345)) as client:
        result=rpc(client,scoped_config.api_key,'job_cancel',{'job_id':'owned'})
        assert not result['result'].get('isError'),result
        response=client.post('/api/v1/jobs/owned/cancel',headers={'X-AgentPorter-Key':scoped_config.api_key})
        assert response.status_code==200,response.text
        result=rpc(client,scoped_config.api_key,'job_cancel',{'job_id':'unrelated'})
        assert result['result'].get('isError'),result
        response=client.post('/api/v1/jobs/unrelated/cancel',headers={'X-AgentPorter-Key':scoped_config.api_key})
        assert response.status_code==403,response.text
    assert seen==['owned','owned']
