import json,re,secrets,time,urllib.request,urllib.parse,urllib.error
from pathlib import Path
root=Path('/home/yeli/repos/AgentPorter');evidence=root/'artifacts/bcc-consolidation-20261112/shared-cli-delegated-write-final-20261113.json'
relative='artifacts/bcc-consolidation-20261112/shared-cli-delegated-write-probe-final-20261113.txt';target=root/relative
key=next(x.split('=',1)[1].strip() for x in Path('/home/yeli/.config/agentporter/secrets.env').read_text().splitlines() if x.startswith('AGENTPORTER_API_KEY='))
class NoRedirect(urllib.request.HTTPRedirectHandler):
 def redirect_request(self,*a,**kw):raise PermissionError('Redirect refused')
opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect())
def api(path,body=None):
 request=urllib.request.Request('http://127.0.0.1:8765'+path,data=None if body is None else json.dumps(body).encode(),headers={'X-AgentPorter-Key':key,'Content-Type':'application/json'})
 for attempt in range(5):
  try:
   with opener.open(request,timeout=90) as response:return json.loads(response.read(2*1024**2))
  except urllib.error.HTTPError as error:
   if error.code!=429 or attempt==4:raise
   time.sleep(min(15,max(1,float(error.headers.get('Retry-After','15')))))
def save():evidence.write_text(json.dumps(row,indent=2))
if evidence.exists():row=json.loads(evidence.read_text())
else:
 assert not target.exists()
 row={'request':{'request_id':secrets.token_hex(16),'agent':'liz','read_only':False,'allow_commit':False,'allow_push':False,'reasoning_effort':'low','purpose':'Verify delegated writable BCC publication after credential repair','task':'Create /workspace/'+relative+' with exactly one line BCC_WRITABLE_WORKER_OK followed by a newline. Modify no other file. Use a local Python write and read back only that file. Do not use Git, network, credentials or other agents. After verification respond only with BCC_DELEGATED_WRITE_OK.'},'canonical_file':relative}
 save()
if not row.get('job_id'):
 q=urllib.parse.urlencode({'provider':'codex','profile':'liz','model':'gpt-6.1-sol','live':'true','allow_cached_fallback':'false'})
 row['qman']=api('/api/v1/qman/consult?'+q);assert row['qman']['agentporter']['cached_fallback_used'] is False;save()
 reply=api('/api/v1/workspaces/agentporter/agents/dispatch',row['request']);row['job_id']=reply['job_id'];save();print(json.dumps({'job_id':row['job_id'],'status':'admitted'}),flush=True)
terminal={'completed','failed','cancelled','timed_out','cleanup_failed','interrupted','recovered','output_limit_exceeded'}
deadline=time.monotonic()+240
while time.monotonic()<deadline:
 status=api('/api/v1/jobs/'+row['job_id']+'/status');row['status']=status;save()
 if status['status'] in terminal:break
 time.sleep(5)
result=api('/api/v1/jobs/'+row['job_id']+'/result',{'cursor':0,'max_bytes':65536})
output='\n'.join(str(result.get(k,'')) for k in ('stdout','stderr','output'))
row.update(response_tail=output[-8000:],canonical_exists=target.exists(),canonical_content_matches=target.exists() and target.read_bytes()==b'BCC_WRITABLE_WORKER_OK\n')
row['passed']=row['status']['status']=='completed' and row['status'].get('exit_code')==0 and row['canonical_content_matches'] and bool(re.search(r'(?m)^BCC_DELEGATED_WRITE_OK\s*$',output));save()
print(json.dumps({'passed':row['passed'],'job_id':row['job_id'],'status':row['status']['status'],'canonical_content_matches':row['canonical_content_matches'],'evidence':str(evidence)}),flush=True)
raise SystemExit(0 if row['passed'] else 1)
