#!/usr/bin/env python3
"""Authenticated fresh catalog/schema/denial checks; no mutation or model calls."""
import json
from pathlib import Path
import time,urllib.request,urllib.error
ROOT=Path(__file__).resolve().parents[1]
OUT=ROOT/'artifacts/bcc-chatgpt-audit-20261113'

def request(path,body=None):
 key=next(x.split('=',1)[1].strip() for x in Path('/home/yeli/.config/agentporter/secrets.env').read_text().splitlines() if x.startswith('AGENTPORTER_API_KEY='))
 class NoRedirect(urllib.request.HTTPRedirectHandler):
  def redirect_request(self,*args,**kwargs):raise PermissionError('Redirect refused')
 opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect())
 r=urllib.request.Request('http://127.0.0.1:8765'+path,data=None if body is None else json.dumps(body).encode(),headers={'X-AgentPorter-Key':key,'Content-Type':'application/json','Accept':'application/json, text/event-stream'})
 try:
  with opener.open(r,timeout=120) as f:code=f.status;raw=f.read(8*1024**2).decode()
 except urllib.error.HTTPError as error:code=error.code;raw=error.read(65536).decode()
 if raw.startswith('event:'):raw=next(line[6:] for line in raw.splitlines() if line.startswith('data: '))
 return code,json.loads(raw)

def rpc(name,args):return request('/mcp',{'jsonrpc':'2.0','id':1,'method':'tools/call','params':{'name':name,'arguments':args}})[1]
def content(value):
 assert 'result' in value and not value['result'].get('isError'), 'MCP request refused'
 return json.loads(value['result']['content'][0]['text'])
def shape(schema):
 value={k:v for k,v in schema.items() if k in {'type','anyOf','enum','default','minLength','maxLength','pattern','minimum','maximum','minItems','maxItems','items'}}
 if any(v.get('type')=='null' for v in schema.get('anyOf',[])):value.setdefault('default',None)
 return value
def main():
 started=time.time();code,rest=request('/openapi.json');assert code==200
 _,mcp=request('/mcp',{'jsonrpc':'2.0','id':1,'method':'tools/list','params':{}})
 tools={row['name']:row for row in mcp['result']['tools']}
 operations={v['operationId']:v for p in rest['paths'].values() for v in p.values() if isinstance(v,dict) and 'operationId' in v}
 assert len(operations)==31 and len(tools)==55
 assert 'git_push' in tools and not any('/git/push' in p for p in rest['paths'])
 caps=content(rpc('get_capabilities',{}));assert set(caps['supported_tools'])==set(tools)
 assert caps['unpublished_actions']==[]
 matrix={row['action']:row['mode'] for row in caps['action_matrix']};assert matrix['git_commit']==matrix['git_push']=='LOCKED'
 parity={}
 for tool,body_name in [('dispatch_agent','DispatchAgentRequest'),('git_commit','GitCommitRequest'),('git_fetch','GitFetchRequest'),('git_pull','GitPullRequest'),('git_add','GitAddRequest'),('git_checkout','GitCheckoutRequest')]:
  a=tools[tool]['inputSchema'];b=rest['components']['schemas'][body_name]
  a_fields=set(a['properties'])-{'workspace_id'};b_fields=set(b['properties'])
  assert a_fields==b_fields,(tool,'field mismatch',sorted(a_fields^b_fields))
  for name in b_fields:assert shape(a['properties'][name])==shape(b['properties'][name]),(tool,name)
  assert set(a.get('required',[]))-{'workspace_id'}==set(b.get('required',[])),tool
  parity[tool]={'shared_fields':len(b_fields),'required_defaults_types_match':True,'workspace_id':'REST path / MCP required argument'}
 q_rest={p['name']:p['schema'] for p in operations['bcc_qman_consult']['parameters']};q_mcp=tools['qman_consult']['inputSchema']['properties']
 assert set(q_rest)==set(q_mcp)-{'workspace_id'}
 for name in q_rest:assert shape(q_rest[name])==shape(q_mcp[name]),('qman',name)
 parity['qman_consult']={'required_defaults_types_match':True,'workspace_id':'REST fixed qman / MCP requires qman'}
 denial={}
 for action in ('commit','push'):
  for prepare in (False,True):
   args={'workspace_id':'agentporter','prepare_only':prepare}
   if action=='commit':args['message']='AUDIT DENIAL ONLY'
   result=rpc('git_'+action,args)
   assert not result['result'].get('isError',False)
   denied=result['result']['structuredContent']
   assert denied['status']=='denied' and denied['executed'] is False and denied['error']['code']=='POLICY_DENIED'
   rest_args={k:v for k,v in args.items() if k!='workspace_id'}
   status,rest_error=request('/api/v1/workspaces/agentporter/git/'+action,rest_args)
   assert status==403 and rest_error['detail']['code']=='POLICY_DENIED'
   denial[action+str(prepare)]={'status':'denied','executed':False,'code':'POLICY_DENIED','mode':'LOCKED'}
 code,deploy=request('/api/v1/server/deploy-info');assert code==200 and not deploy['stale'] and deploy['loaded_fingerprint']==deploy['disk_fingerprint']
 for name,value in [('rest-catalog-after',rest),('mcp-catalog-after',mcp),('capabilities-after',caps)]:
  (OUT/(name+'.json')).write_text(json.dumps(value,indent=2)+'\n')
 value={'passed':True,'started_epoch':started,'finished_epoch':time.time(),'transport':'local live authenticated BCC REST/MCP; not external ChatGPT','rest_operations':len(operations),'mcp_tools':len(tools),'schema_parity':parity,'git_denials':denial,'deploy':{k:deploy[k] for k in ('pid','stale','loaded_fingerprint','disk_fingerprint')}}
 (OUT/'live-interface-after.json').write_text(json.dumps(value,indent=2)+'\n');print(json.dumps(value))
if __name__=='__main__':main()
