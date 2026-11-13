#!/usr/bin/env python3
"""Verify the activated BCC repair without model calls or Git publication.

Writes one canary inside the authorized AgentPorter artifact directory. Native
access credential issuance is checked separately under the actual worker UID.
Never prints, saves or transmits the gateway API key outside its existing origin.
"""
import json
import os
from pathlib import Path
import secrets
import subprocess
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request

REPO = Path('/home/yeli/repos/AgentPorter')
CONTROL = Path('/var/lib/agentporter-bcc/consolidation-20261113-10')


def main():
    assert os.getuid() == 2056259175, 'Run live workspace verification as the repository owner'
    state = json.loads(Path('/tmp/bcc-consolidation-active-status-20261112.json').read_text())
    assert state['phase'] in {'active_pending_live_acceptance','accepted'}, 'Activate and verify rollback first'
    key = next(line.split('=',1)[1].strip() for line in
        Path('/home/yeli/.config/agentporter/secrets.env').read_text().splitlines()
        if line.startswith('AGENTPORTER_API_KEY='))
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *a, **k):
            raise PermissionError('Verification redirect refused')
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    evidence = {'transport': 'authenticated local B6 REST; not the external ChatGPT connection', 'checks': {}}
    def api(path, body=None, *, port=8765):
        secret = key
        request = urllib.request.Request('http://127.0.0.1:'+str(port)+path,
            data=None if body is None else json.dumps(body).encode(),
            headers={'X-AgentPorter-Key': secret, 'Content-Type': 'application/json'})
        try:
            with opener.open(request, timeout=90) as response:
                return response.status, json.loads(response.read(4*1024**2))
        except urllib.error.HTTPError as error:
            return error.code, json.loads(error.read(65536))
    for role, port in [('gateway',8765)]:
        status, value = api('/api/v1/server/deploy-info', port=port)
        assert status == 200 and value['stale'] is False
        assert value['loaded_fingerprint'] == value['disk_fingerprint'] == state['new'][role]['fingerprint']
        evidence['checks'][role+'_source'] = {'passed': True, 'pid': value['pid'], 'fingerprint': value['loaded_fingerprint']}
        for action in ('commit', 'push'):
            body = {'message': 'BCC verification: must be denied'} if action == 'commit' else {}
            status, value = api('/api/v1/workspaces/agentporter/git/'+action, body, port=port)
            assert status == 403, (role,action,status)
            evidence['checks'][role+'_'+action+'_denied'] = {'http_status': status}
    status, schema = api('/openapi.json')
    assert status == 200
    text = json.dumps(schema)
    assert 'writable workers can commit without confirmation' not in text
    assert 'workspace commits execute directly' not in text
    assert 'Must be false' in schema['components']['schemas']['DispatchAgentRequest']['properties']['allow_commit']['description']
    operations = [v['operationId'] for methods in schema['paths'].values() for v in methods.values()
                  if isinstance(v,dict) and 'operationId' in v]
    assert all(name.startswith('bcc_') for name in operations)
    evidence['checks']['generated_schema'] = {'operations': len(operations), 'stale_commit_instructions': False}
    (REPO/'artifacts/bcc-consolidation-20261112/active-openapi.json').write_text(json.dumps(schema,indent=2))
    status, rows = api('/api/v1/workspaces/agentporter/agents/list')
    assert status == 200
    selected = [r for r in rows if r['agent'] in {'jax','liz','prof'}]
    assert len(selected) == 3 and all(r.get('available') and r.get('delegatable') for r in selected)
    assert all('agentporter' in r.get('public_writable_dispatch_workspaces',[]) for r in selected)
    evidence['checks']['native_worker_inventory'] = {'available': [r['agent'] for r in selected], 'writable_agentporter': True}
    name = 'live-persistence-'+secrets.token_hex(6)+'.txt'
    relative = 'artifacts/bcc-consolidation-20261112/'+name
    canonical = REPO/relative
    assert not canonical.exists()
    with tempfile.TemporaryDirectory(prefix='bcc-host-isolation-') as host:
        sentinel = Path(host)/'sentinel'
        sentinel.write_text('host-only')
        code = ("from pathlib import Path; p=Path("+repr(relative)+"); p.write_text('BCC_PERSISTENT_EDIT_OK\\n'); "
                "assert not Path('/run/agentporter-bcc-auth/auth.sock').exists(); "
                "assert not Path('/home/yeli/.codex/auth.json').exists(); "
                "assert not Path("+repr(str(sentinel))+").exists(); print('BCC_PERSISTENT_EDIT_OK',flush=True)")
        status, value = api('/api/v1/workspaces/agentporter/exec/run',
            {'argv':['/usr/bin/python3','-c',code], 'timeout_seconds':60})
        assert status == 200 and value['exit_code'] == 0 and 'BCC_PERSISTENT_EDIT_OK' in value['stdout'], (status,value)
        assert canonical.read_text() == 'BCC_PERSISTENT_EDIT_OK\n' and sentinel.read_text() == 'host-only'
    status, value = api('/api/v1/workspaces/agentporter/files/read', {'path':relative})
    assert status == 200 and value['content'] == canonical.read_text()
    evidence['checks']['workspace_persistence_and_isolation'] = {'passed':True,'canonical_file':relative}
    for profile in ('jax','liz','prof'):
        query = urllib.parse.urlencode({'provider':'codex','profile':profile,'live':'true','allow_cached_fallback':'false'})
        start = time.monotonic()
        status, value = api('/api/v1/qman/consult?'+query)
        assert status == 200 and value['agentporter']['cached_fallback_used'] is False
        transport = value['agentporter']
        assert transport['mode'] == 'live' or transport.get('reason') == 'live_quota_capability_not_authorized'
        evidence['checks']['qman_'+profile] = {'duration_seconds':round(time.monotonic()-start,3), 'transport':transport,
            'agents':value.get('agents'), 'interpretation':'preserve reported identity and entitlement limitations'}
    _, value = api('/api/v1/qman/consult?provider=all&profile=all&live=true&allow_cached_fallback=false')
    assert value['agentporter']['reason'] == 'live_quota_requires_exact_provider_profile'
    evidence['checks']['qman_exact_scope'] = {'passed':True}
    evidence['passed'] = True
    destination = REPO/'artifacts/bcc-consolidation-20261112/live-acceptance.json'
    destination.write_text(json.dumps(evidence, indent=2))
    print(json.dumps({'passed':True,'evidence':str(destination),'external_chatgpt_verified':False}))


if __name__ == '__main__':
    main()
