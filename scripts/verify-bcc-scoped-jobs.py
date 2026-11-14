#!/usr/bin/env python3
"""One ordinary execution and one exact Jax dispatch; no uncertain retries."""
import hashlib,json,runpy,secrets,subprocess,time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];OUT=ROOT/'artifacts/bcc-chatgpt-audit-20261113'
http=runpy.run_path(str(ROOT/'scripts/verify-bcc-audit-live.py'));request,rpc,content=http['request'],http['rpc'],http['content']
def git(*args):return subprocess.check_output(['/usr/bin/git',*args],cwd=ROOT,env={'PATH':'/usr/bin:/bin','GIT_OPTIONAL_LOCKS':'0'})
def metadata():return {p.relative_to(ROOT/'.git').as_posix():hashlib.sha256(p.read_bytes()).hexdigest() for p in (ROOT/'.git').rglob('*') if p.is_file()}
def main():
 before=metadata();args=['bcc-python','-B','scripts/bcc-scoped-verification.py','--expected-head-inode',str((ROOT/'.git/HEAD').stat().st_ino),'--expected-refs-sha256',hashlib.sha256(git('for-each-ref','--format=%(refname)%00%(objectname)%00%(symref)')).hexdigest()]
 status,result=request('/api/v1/workspaces/agentporter/exec/run',{'argv':args,'timeout_seconds':120})
 assert status==200,'Ordinary execution transport refused'
 (OUT/'ordinary-execution.json').write_text(json.dumps({'observed_epoch':time.time(),'transport':'local authenticated REST','response':result},indent=2)+'\n')
 print(json.dumps({'ordinary_http':status,'exit_code':result.get('exit_code'),'stdout':result.get('stdout')}),flush=True)
 assert result['exit_code']==0
 q=content(rpc('qman_consult',{'workspace_id':'qman','provider':'codex','profile':'jax','model':'gpt-6.1-terra','live':True,'allow_cached_fallback':False}))
 assert q['agentporter']['mode']=='live' and not q['agentporter']['cached_fallback_used']
 (OUT/'jax-quota-before-dispatch.json').write_text(json.dumps({'observed_epoch':time.time(),'value':q},indent=2)+'\n')
 print(json.dumps({'dispatch_identity':'jax','model':'gpt-6.1-terra','reasoning':'low','live_quota_obtained':True,'cached_fallback':False,'entitlement':'not inferred from quota'}),flush=True)
 request_id=secrets.token_hex(16);destination='artifacts/bcc-chatgpt-audit-20261113/jax-scoped-tests.json'
 command=args+['--receipt',destination]
 task='Run exactly this argv from the repository root: '+json.dumps(command)+'. It runs portable fixture tests and prints a JSON verification result. Do not edit code, Git metadata, or any other repository file. Report the actual exit code and JSON result. Do not commit or push; do not use another account, model, host, or network tool. Do not read credentials. If this command fails, report it without changing tests or retrying model execution.'
 packet={'agent':'jax','task':task,'purpose':'Owner-requested independent verification of BCC Git isolation and Python test runtime','model':'gpt-6.1-terra','reasoning_effort':'low','allow_commit':False,'allow_push':False,'read_only':False,'request_id':request_id}
 ledger={'request_id':request_id,'packet':packet,'status':'prepared','created_at_epoch':time.time()};ledger_path=OUT/'jax-dispatch.json';ledger_path.write_text(json.dumps(ledger,indent=2)+'\n')
 status,value=request('/api/v1/workspaces/agentporter/agents/dispatch',packet);ledger.update(http_status=status,response=value);ledger_path.write_text(json.dumps(ledger,indent=2)+'\n')
 assert status==200 and value.get('job_id'),'Dispatch refused; do not retry'
 handle=value['job_id'];print(json.dumps({'job_id':handle,'admission':value.get('status')}),flush=True)
 deadline=time.monotonic()+300
 while time.monotonic()<deadline:
  time.sleep(5);status,state=request('/api/v1/jobs/'+handle+'/status')
  if status==429:continue
  assert status==200
  if state['status'] in ('completed','failed','rejected','cancelled','timed_out','cleanup_failed'):
   break
 else:raise TimeoutError('Jax pending; reconcile existing handle, never repeat dispatch')
 status,value=request('/api/v1/jobs/'+handle+'/result',{})
 (OUT/'jax-job-result.json').write_text(json.dumps({'observed_epoch':time.time(),'http_status':status,'value':value},indent=2)+'\n')
 assert status==200 and value['status']=='completed' and value['exit_code']==0
 proof=json.loads((ROOT/destination).read_text());assert proof['passed'] and proof['portable_tests']['exit_code']==0
 assert metadata()==before,'Canonical Git metadata changed during live scoped verification'
 summary={'passed':True,'transport':'local live REST dispatch, not external ChatGPT','job_id':handle,'jax_exit_code':value['exit_code'],'jax_proof':proof,'canonical_git_metadata_unchanged':True}
 (OUT/'live-scoped-summary.json').write_text(json.dumps(summary,indent=2)+'\n');print(json.dumps(summary),flush=True)
if __name__=='__main__':main()
