"""A LOCKED request never touches a repo and retains a public reason over MCP/REST."""
import json
from unittest.mock import Mock
import pytest
import yaml
from fastapi.testclient import TestClient
from agentporter.server import create_asgi_app
from agentporter.tools.git import create_git_tools


@pytest.mark.parametrize('action', ['commit', 'push'])
@pytest.mark.parametrize('prepare', [False, True])
def test_locked_valid_calls_explain_policy_before_any_git_backend(temp_config, monkeypatch, action, prepare):
    temp_config.security.allowed_hosts.append('testserver')
    p=temp_config.config_dir/'action-policy.yaml'
    p.write_text(yaml.safe_dump({'version':1,'action_modes':{'git_commit':'LOCKED','git_push':'LOCKED'}}));p.chmod(0o600)
    public=temp_config.config_dir/'public-client-policy.yaml'
    public.write_text(yaml.safe_dump({'version':1,'workspaces':{}}));public.chmod(0o600)
    calls=Mock(side_effect=AssertionError('A policy refusal must not touch repository state'))
    app=create_asgi_app(temp_config)
    from agentporter.workspaces.registry import WorkspaceRegistry
    monkeypatch.setattr(WorkspaceRegistry,'get',calls)
    with TestClient(app) as client:
        headers={'X-AgentPorter-Key':temp_config.api_key,'Accept':'application/json, text/event-stream'}
        args={'workspace_id':'demo','prepare_only':prepare}
        if action=='commit':args['message']='AUDIT DENIAL ONLY'
        response=client.post('/mcp',headers=headers,json={'jsonrpc':'2.0','id':1,'method':'tools/call','params':{'name':'git_'+action,'arguments':args}})
        text=response.text
        value=json.loads(next(x[6:] for x in text.splitlines() if x.startswith('data: '))) if text.startswith('event:') else response.json()
        assert 'result' in value, value
        assert value['result'].get('isError',False) is False
        denied=value['result']['structuredContent']
        assert denied['status']=='denied' and denied['executed'] is False
        assert denied['error']=={'code':'POLICY_DENIED','action':'git_'+action,'mode':'LOCKED','reason':'action_locked'}
        body={k:v for k,v in args.items() if k!='workspace_id'}
        response=client.post('/api/v1/workspaces/demo/git/'+action,headers=headers,json=body)
        assert response.status_code==403,response.text
        assert response.json()['detail']=={'code':'POLICY_DENIED','action':'git_'+action,'mode':'LOCKED','reason':'action_locked'}
    calls.assert_not_called()
