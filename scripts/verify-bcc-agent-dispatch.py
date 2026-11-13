#!/usr/bin/env python3
"""Three bounded, read-only B6 inference checks with durable idempotency IDs.

Uses each installed profile's configured model; no account/model fallback.
One request per profile, recovered by the same request_id if admission output
is lost. No Git operations, file edits, nested workers or tools are requested.
"""
import json
import re
import secrets
import time
from pathlib import Path
import urllib.error
import urllib.parse
import urllib.request

ROOT = Path('/home/yeli/repos/AgentPorter/artifacts/bcc-consolidation-20261112')
LEDGER = ROOT/'native-agent-smoke-20261113.json'
TERMINAL = {'completed','failed','cancelled','timed_out','cleanup_failed','interrupted',
    'output_limit_exceeded','recovered','rejected'}


def main():
    global LEDGER
    import argparse
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--ledger-name',default=LEDGER.name)
    parser.add_argument('--agent',choices=('jax','liz','prof'),action='append')
    args=parser.parse_args()
    assert Path(args.ledger_name).name==args.ledger_name and args.ledger_name.endswith('.json')
    LEDGER=ROOT/args.ledger_name
    key = next(line.split('=',1)[1].strip() for line in
        Path('/home/yeli/.config/agentporter/secrets.env').read_text().splitlines()
        if line.startswith('AGENTPORTER_API_KEY='))
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *args, **kwargs):
            raise PermissionError('B6 verification redirect refused')
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    def api(path, body=None, timeout=45):
        request = urllib.request.Request('http://127.0.0.1:8765'+path,
            data=None if body is None else json.dumps(body).encode(),
            headers={'X-AgentPorter-Key':key,'Content-Type':'application/json'})
        for attempt in range(5):
            try:
                with opener.open(request,timeout=timeout) as response:
                    return json.loads(response.read(2*1024**2))
            except urllib.error.HTTPError as error:
                if error.code!=429 or attempt==4:
                    raise
                time.sleep(min(15,max(1,float(error.headers.get('Retry-After','15')))))
    def save():
        temporary = LEDGER.with_suffix('.pending')
        temporary.write_text(json.dumps(ledger,indent=2))
        temporary.replace(LEDGER)
    if LEDGER.exists():
        ledger = json.loads(LEDGER.read_text())
    else:
        ledger = {'workspace':'agentporter','read_only':True,'model_calls_requested':3,'jobs':{}}
        for agent, model in [('jax','gpt-6.1-terra'),('liz','gpt-6.1-sol'),('prof','gpt-6.1-terra')]:
            if args.agent and agent not in args.agent:
                continue
            marker = 'BCC_'+agent.upper()+'_NATIVE_SMOKE_OK'
            ledger['jobs'][agent] = {'configured_model':model,'effort':'low','marker':marker,
                'payload':{'request_id':secrets.token_hex(16),'agent':agent,'read_only':True,
                    'allow_commit':False,'allow_push':False,'reasoning_effort':'low',
                    'purpose':'Verify repaired BCC native response and cleanup',
                    'task':'Respond exactly with '+marker+'. Do not call any tools, read files, modify files, '
                           'access credentials, run Git or launch other agents. This is one read-only response check.'}}
        save()
    for agent, row in ledger['jobs'].items():
        if row.get('job_id') or row.get('verified'):
            continue
        query = urllib.parse.urlencode({'provider':'codex','profile':agent,'model':row['configured_model'],
            'live':'true','allow_cached_fallback':'false'})
        quota = api('/api/v1/qman/consult?'+query)
        assert quota['agentporter']['cached_fallback_used'] is False
        row['live_qman'] = {'agentporter':quota['agentporter'],'agents':quota.get('agents'),
            'model_cards':quota.get('model_cards_and_api_cost_reference')}
        print(json.dumps({'agent':agent,'model':row['configured_model'],'effort':row['effort'],
            'live_quota':quota['agentporter'].get('mode'),'quota_reason':quota['agentporter'].get('reason'),
            'cached_fallback_used':False,'metrics':quota.get('agents'),
            'cost_and_entitlement':'unknown unless independently reported by source'}),flush=True)
        row['admission_intent_at'] = time.time()
        save()
        reply = api('/api/v1/workspaces/agentporter/agents/dispatch',row['payload'],timeout=90)
        assert isinstance(reply.get('job_id'),str) and reply['job_id']
        row.update(job_id=reply['job_id'],admission=reply)
        save()
        print(json.dumps({'agent':agent,'job_id':row['job_id'],'status':'admitted'}),flush=True)
    deadline = time.monotonic()+240
    while time.monotonic()<deadline:
        pending = False
        for agent,row in ledger['jobs'].items():
            if row.get('terminal_status'):
                continue
            status = api('/api/v1/jobs/'+row['job_id']+'/status')
            row['latest_status'] = status
            if status['status'] not in TERMINAL:
                pending = True
                continue
            result = api('/api/v1/jobs/'+row['job_id']+'/result',{'cursor':0,'max_bytes':65536})
            output = '\n'.join(str(result.get(k,'')) for k in ('stdout','stderr','output'))
            # The task contains the marker inline. Require an actual standalone
            # answer or a native JSON agent-message item, not echoed prompt text.
            answer = bool(re.search(r'(?m)^'+re.escape(row['marker'])+r'\s*$',output))
            for line in output.splitlines():
                try:
                    event = json.loads(line)
                except ValueError:
                    continue
                item = event.get('item',{}) if isinstance(event,dict) else {}
                if item.get('type') == 'agent_message' and item.get('text','').strip() == row['marker']:
                    answer = True
            row.update(terminal_status=status['status'],exit_code=status.get('exit_code'),answer_verified=answer,
                forbidden_auth_errors=any(x in output.lower() for x in ('refresh_token_reused','token_expired','401 unauthorized')),
                response_tail=output[-5000:])
            row['verified'] = status['status']=='completed' and status.get('exit_code')==0 and answer and not row['forbidden_auth_errors']
            save()
            print(json.dumps({'agent':agent,'job_id':row['job_id'],'status':row['terminal_status'],
                'answer_verified':answer,'verified':row['verified']}),flush=True)
        save()
        if not pending:
            break
        time.sleep(5)
    ledger['passed'] = all(row.get('verified') for row in ledger['jobs'].values())
    save()
    print(json.dumps({'passed':ledger['passed'],'ledger':str(LEDGER),'jobs':{
        agent:{k:row.get(k) for k in ('job_id','terminal_status','verified')}
        for agent,row in ledger['jobs'].items()}}),flush=True)
    raise SystemExit(0 if ledger['passed'] else 1)


if __name__ == '__main__':
    main()
