"""Protected action matrix is visible and cannot bypass receiver launch gates."""
import json
from pathlib import Path

import pytest
import yaml
from fastapi.testclient import TestClient
from agentporter import server
from agentporter.action_policy import DEFAULT_ACTION_MODES
from agentporter.agents.production_relay import RelayLedger
from tests.security.test_relay_no_launch_recovery import receiving
from tests.security.test_writable_public_delegation import configured


def write_policy(config,workspace,agent='copilot_agent'):
    path=Path(config)/'action-policy.yaml'
    path.write_text(yaml.safe_dump({'version':1,'action_modes':{},'scoped_modes':[
        {'action':'git_commit','workspace_id':workspace,'agent':agent,'mode':'LOCKED'}]}))
    path.chmod(0o600)


def test_capabilities_expose_one_pure_effective_row_for_every_action(temp_config,tmp_path):
    project=tmp_path/'matrix-project';project.mkdir()
    temp_config.workspaces={'sample':{'path':str(project),'writable':True}}
    write_policy(temp_config.config_dir,'sample')
    _,context=server.build_mcp_server(temp_config)
    rows=context['tools']['get_capabilities']()['action_matrix']
    assert len(rows)==len(DEFAULT_ACTION_MODES) and {row['action'] for row in rows}==set(DEFAULT_ACTION_MODES)
    assert all(set(row)=={'action','mode','scope_condition','backend_checks_required'} for row in rows)
    assert all(row['backend_checks_required'] is True for row in rows)
    assert 'sample' not in json.dumps(rows) and 'copilot_agent' not in json.dumps(rows)
    selected=context['operator_action_policy'].snapshot(workspace_id='sample',agent='copilot_agent')
    assert next(row for row in selected if row['action']=='git_commit')['mode']=='LOCKED'
    assert next(row for row in rows if row['action']=='git_push')['mode']=='LOCKED'


def test_public_inventory_and_dispatch_reflect_scoped_native_commit_restriction(configured):
    config,_,dispatch=configured
    write_policy(config.config_dir,'project')
    with TestClient(server.create_asgi_app(config)) as client:
        headers={'X-AgentPorter-Key':config.api_key};endpoint='/api/v1/workspaces/project/agents/'
        response=client.get(endpoint+'list',headers=headers)
        assert response.status_code==200,response.text
        rows={row['agent']:row for row in response.json()}
        assert rows['copilot_agent']['public_writable_dispatch_workspaces']==[]
        assert rows['copilot_agent']['public_dispatch_read_only'] is True and rows['copilot_agent']['delegatable'] is True
        assert 'protected dispatch/commit policy' in rows['copilot_agent']['writable_delegation_reason']
        assert rows['codex_impl']['public_writable_dispatch_workspaces']==['project']
        assert client.post(endpoint+'dispatch',headers=headers,json={'agent':'copilot_agent','task':'no native commit capability','read_only':False}).status_code==403
        dispatch.assert_not_called()
        assert client.post(endpoint+'dispatch',headers=headers,json={'agent':'copilot_agent','task':'read-only remains allowed','read_only':True}).status_code==200
        assert dispatch.call_count==1 and dispatch.call_args.kwargs['read_only'] is True


@pytest.fixture
def restricted_receiver(monkeypatch,request):
    original=server.OperatorActionPolicy
    def load(config,*args,**kwargs):
        if Path(config).name=='worker-config':
            from tests.security.relay_fixture import plan
            write_policy(config,plan.FIXTURE_ID)
        return original(config,*args,**kwargs)
    monkeypatch.setattr(server,'OperatorActionPolicy',load)
    return request.getfixturevalue('receiving')


def test_receiving_relay_enforces_its_own_scoped_commit_deny_before_dispatch(restricted_receiver):
    from tests.security.relay_fixture import plan
    f=restricted_receiver;f.release.set();ledger=RelayLedger(f.worker.state_dir)
    def data(key,agent='copilot_agent',read_only=False):
        return {'request_id':key,'workspace_id':plan.FIXTURE_ID,'agent':agent,'task':'scoped receiver policy','read_only':read_only}
    code,_=f.raw('dispatch_agent',data('a'*32))
    assert code==403 and f.calls==[]
    assert ledger.get_request_state('a'*32)==(None,plan.FIXTURE_ID,'copilot_agent',0)
    assert ledger.reserve('a'*32,plan.FIXTURE_ID,'copilot_agent')==(None,plan.FIXTURE_ID,'copilot_agent')
    assert f.raw('lookup_dispatch',{'request_id':'a'*32})[1]['status']=='not_launched'
    # The synthetic backend rejects after being called. Count distinguishes
    # that independent refusal from a policy gate wrongly denying allowed scopes.
    assert f.raw('dispatch_agent',data('b'*32,read_only=True))[0]==403
    assert len(f.calls)==1 and f.calls[0]['read_only'] is True
    assert f.raw('dispatch_agent',data('c'*32,agent='codex_impl'))[0]==403
    assert len(f.calls)==2 and f.calls[1]['agent']=='codex_impl'
    assert f.raw('dispatch_agent',data('d'*32,read_only='false'))[0]==403
    assert len(f.calls)==2 and ledger.get_request('d'*32) is None


def test_gateway_independently_denies_writable_dispatch_before_relay_reservation(receiving):
    from tests.security.relay_fixture import plan
    f=receiving;f.release.set();write_policy(f.config.config_dir,plan.FIXTURE_ID)
    with TestClient(server.create_asgi_app(f.config)) as client:
        response=client.post('/api/v1/workspaces/'+plan.FIXTURE_ID+'/agents/dispatch',
            headers={'X-AgentPorter-Key':f.config.api_key},json={'agent':'copilot_agent','task':'gateway policy','read_only':False})
        assert response.status_code==403,response.text
    assert f.calls==[]
    with RelayLedger(f.config.state_dir)._db() as db:
        assert db.execute('SELECT count(*) FROM jobs').fetchone()[0]==0
