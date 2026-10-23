import asyncio,datetime,hashlib,json,pathlib,re
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client
from mcp.shared._httpx_utils import create_mcp_http_client
from mcp.types import PaginatedRequestParams
PUBLIC='https://1xs4h6qn-8876.use.devtunnels.ms/mcp'
LOCAL='http://127.0.0.1:8876/mcp'
FP='099b88c95f0fb23e33554e85a426e1b25b9fbba9ca3fe4fffd1ab4869b5da315'
ROOT=pathlib.Path('/home/yeli/agent-work/agentporter-dev')
OUT=ROOT/'docs/evidence/a7dev-project-access-retry-20261021/live-closeout.json'
key=next(line.partition('=')[2].strip().strip('\"\'') for line in pathlib.Path('/tmp/agentporter-development-asgard/config/secrets.env').read_text().splitlines() if line.startswith('AGENTPORTER_API_KEY='))
record={'passed':False,'timestamp':datetime.datetime.now(datetime.timezone.utc).isoformat(),'endpoints':[],'provider_jobs':[]}
def save():OUT.write_text(json.dumps(record,indent=2)+'\n')
def unpack(result):
 data=result.structured_content
 if data is None:
  raw=''.join(c.text for c in result.content if c.type=='text')
  try:data=json.loads(raw)
  except ValueError:data={'message':raw}
 if isinstance(data,dict) and set(data)=={'result'}:data=data['result']
 assert not result.is_error, 'Public MCP error; no sensitive payload printed'
 return data
async def main():
 for endpoint in (PUBLIC,LOCAL):
  async with create_mcp_http_client(headers={'X-AgentPorter-Key':key,'X-Tunnel-Skip-AntiPhishing-Page':'true'}) as client:
   client.follow_redirects=False
   async with streamable_http_client(endpoint,http_client=client) as streams:
    async with ClientSession(streams[0],streams[1]) as session:
     await session.initialize()
     async def call(name,args):return unpack(await asyncio.wait_for(session.call_tool(name,args),120))
     deployment=await call('server_deploy_info',{})
     assert deployment['loaded_fingerprint']==deployment['disk_fingerprint']==FP and not deployment['stale']
     record['endpoints'].append({'endpoint':endpoint,'deployment':deployment});save()
     if endpoint==LOCAL:continue
     capabilities=await call('get_capabilities',{});scope=capabilities['scoped_public_https']
     assert scope['generic_shell_network'] is False and scope['workspaces']==['cranary']
     record['scoped_https']=scope
     tools=[];cursor=None
     while True:
      page=await session.list_tools(params=PaginatedRequestParams(cursor=cursor));tools.extend(page.tools);cursor=page.next_cursor
      if not cursor:break
     download=next(t for t in tools if t.name=='https_download');schema=download.model_dump(by_alias=True)['inputSchema']
     assert schema['properties']['max_bytes']['default']==16777216 and schema['properties']['timeout_seconds']['default']==60
     record['https_download_discoverable']=True
     workspaces=await call('list_workspaces',{});assert len(workspaces)==46
     protected={'obsidian','agentporter','AgentPorter','asgard-hermes-review','repos'}
     ordinary={r['workspace_id'] for r in workspaces}-protected;assert len(ordinary)==41
     agents=await call('list_agents',{})
     for name in ('jax','wei'):
      agent=next(row for row in agents if row['agent']==name)
      assert set(agent['public_dispatch_workspaces'])==ordinary and agent['delegatable']
      if name=='wei':assert agent['default_model']=='opencode/glm-5.3-flash-free'
      record[name]={k:agent.get(k) for k in ('agent','delegatable','default_model','provider','public_dispatch_workspaces','readiness_note')}
     record['ordinary_project_count']=41;record['registered_workspace_count']=46;save()
     for workspace,job_id in [('Qman','job_2dbdd2acf75f44ea9c1d5421'),('m3-poc','job_2a4b547ecaa04191aebcbda3')]:
      job=await call('job_result',{'job_id':job_id,'max_bytes':65536})
      assert job['status']=='completed' and job['exit_code']==0
      stdout=job.get('stdout','');traces=[]
      for line in stdout.splitlines():
       try:event=json.loads(line)
       except (ValueError,TypeError):continue
       if isinstance(event,dict):traces.append(event)
      commands=[event.get('item',{}) for event in traces if event.get('item',{}).get('type')=='command_execution']
      messages=[event.get('item',{}).get('text','') for event in traces if event.get('item',{}).get('type')=='agent_message']
      matched=False
      for command in commands:
       if command.get('exit_code')==0 and ('sha256' in command.get('command','') or 'hashlib' in command.get('command','')):
        hashes=re.findall(r'(?<![0-9a-f])[0-9a-f]{64}(?![0-9a-f])',command.get('aggregated_output',''))
        matched=any(h in message for h in hashes for message in messages) or matched
      entry={'workspace_id':workspace,'job_id':job_id,'status':job['status'],'exit_code':job['exit_code'],'native_trace_events':len(traces),'native_digest_matches_final_answer':matched,'provider':job.get('provider'),'configured_model':job.get('configured_model')}
      record['provider_jobs'].append(entry);save()
      print(json.dumps(entry),flush=True)
     path='data-raw/cran-history/reports/2026-10-21-authorized-acquisition/downloads/PACKAGES-2022-06-30-tool-discovery-737f0fbf30681d97.gz'
     code='import gzip,hashlib,json; from pathlib import Path; p=Path('+repr(path)+'); b=p.read_bytes(); s=hashlib.sha256(b).hexdigest(); assert s=="d2cd86e52af94510adf4e9aed96d4cc7b4172a5a93c3ba0e0094569bf93e4c52"; f=gzip.open(p,"rb"); d=f.read(67108865); f.close(); assert len(d)<=67108864; print(json.dumps({"sha256":s,"bytes":len(b),"expanded_sha256":hashlib.sha256(d).hexdigest(),"gzip_integrity_verified":True}))'
     checked=await call('exec_run',{'workspace_id':'cranary','argv':['python3','-I','-c',code],'timeout_seconds':30,'network_access':False});assert checked['exit_code']==0
     record['existing_binary_receipt_reverified']=json.loads(checked['stdout']);save()
 assert record['endpoints'][0]['deployment']['pid']==record['endpoints'][1]['deployment']['pid']==886920
 record['passed']=True;save();print('PASS: live public/local fingerprints,41-project delegation scope, two completed Jax jobs, free Wei route and saved snapshot integrity.',flush=True)
try:asyncio.run(main())
finally:save()
