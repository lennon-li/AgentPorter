import asyncio,hashlib,importlib.util,json,pathlib,secrets,time
ROOT=pathlib.Path('/home/yeli/agent-work/agentporter-dev')
s=importlib.util.spec_from_file_location('h',ROOT/'scripts/verify-a7dev-cranary-https.py');h=importlib.util.module_from_spec(s);s.loader.exec_module(h)
OUT=ROOT/'docs/evidence/v19-final-closeout-20261021/restored-workspace-acceptance.json'
FP='2a41380b67529e5bb27fa3e00d7a84ced0946989879b3948a97c25f5eeee6ac7'
SHA='a069c3138f2b49c339d5f500f8beff8872d95a125e61a01b8307a7a6eba214fd'
records=[];summary={'passed':False,'calls':records,'public_endpoint':h.PUBLIC}
def save():OUT.write_text(json.dumps(summary,indent=2)+'\n')
async def main():
 key=next(x.partition('=')[2].strip().strip('\"\'') for x in pathlib.Path('/tmp/agentporter-development-asgard/config/secrets.env').read_text().splitlines() if x.startswith('AGENTPORTER_API_KEY='))
 snapshots=[]
 for endpoint in (h.PUBLIC,h.LOCAL):
  async with h.create_mcp_http_client(headers={'X-AgentPorter-Key':key,'X-Tunnel-Skip-AntiPhishing-Page':'true'}) as client:
   client.follow_redirects=False
   async with h.streamable_http_client(endpoint,http_client=client) as streams:
    async with h.ClientSession(streams[0],streams[1]) as session:
     await session.initialize()
     async def call(name,args):
      r=h.unpack(await asyncio.wait_for(session.call_tool(name,args),90));records.append({'endpoint':endpoint,'tool':name,'arguments':args,**r});save();return r
     async def good(name,args):
      r=await call(name,args);assert not r['is_error'],(name,args,r);return r['data']
     async def execute(workspace,argv,network=False,timeout=15):
      r=await good('exec_run',{'workspace_id':workspace,'argv':argv,'timeout_seconds':timeout,'network_access':network});assert r['exit_code']==0,(workspace,argv,r);return r
     d=await good('server_deploy_info',{});assert d['loaded_fingerprint']==d['disk_fingerprint']==FP and not d['stale'];snapshots.append(d)
     if endpoint!=h.PUBLIC:continue
     scopes=await good('list_workspaces',{});assert len(scopes)==46;ids={x['workspace_id'] for x in scopes};assert {'Qman','IRVRI','cranary'}<=ids;summary['workspace_count']=len(scopes)
     for name in ('Qman','IRVRI','cranary'):
      await good('workspace_info',{'workspace_id':name})
      pwd=await execute(name,['pwd']);assert pwd['stdout'].strip()=='/workspace'
      await execute(name,['python3','-V'])
      await execute(name,['git','-c','safe.directory=/workspace','status','--short'])
      print(name+': workspace_info, pwd, Python and Git PASS',flush=True)
     commit='b390ba0afb5f1613572ba4ce3d5d733987edd0bd';base='https://api.github.com/repos/ropensci-archive/rrlite'
     data=await execute('cranary',['curl','-fsS',base+'/commits/'+commit],True);assert json.loads(data['stdout'])['sha']==commit
     src=await execute('cranary',['curl','-fsS',base+'/contents/src/rrlite.c?ref='+commit],True);data=json.loads(src['stdout']);raw=__import__('base64').b64decode(data['content']);assert hashlib.sha256(raw).hexdigest()=='015761af6d0374967c6eb563b211eab208b3b9572673176e659c74fb1d107007';assert hashlib.sha1(('blob '+str(len(raw))+'\0').encode()+raw).hexdigest()==data['sha']
     head=await execute('cranary',['curl','-sSI',base+'/commits/'+commit],True);assert '200' in head['stdout'].splitlines()[0]
     nonce=secrets.token_hex(8)
     receipt=await good('https_download',{'workspace_id':'cranary','url':'https://packagemanager.posit.co/cran/2021-06-30/src/contrib/PACKAGES.gz','filename':'PACKAGES-v19-acceptance-'+nonce+'.gz','max_bytes':16777216,'timeout_seconds':60,'expected_sha256':SHA});assert receipt['http_status']==200 and receipt['sha256']==SHA and receipt['expected_sha256_verified'];summary['snapshot_receipt']=receipt
     code=('import gzip,hashlib,io,json; from pathlib import Path; p=Path('+repr(receipt['path'])+'); assert p.stat().st_size<=16777216; raw=p.read_bytes(); assert hashlib.sha256(raw).hexdigest()=='+repr(SHA)+'; z=gzip.GzipFile(fileobj=io.BytesIO(raw)); expanded=z.read(67108865); z.close(); assert len(expanded)<=67108864; assert hashlib.sha256(expanded).hexdigest()=="2b70321658ff7c6bd3159b62ed8f28708d3544d1b6dce8aa7ce443dc17296280"; print(json.dumps({"sha256":hashlib.sha256(raw).hexdigest(),"expanded_sha256":hashlib.sha256(expanded).hexdigest(),"bytes":len(raw),"expanded_bytes":len(expanded)}))')
     verified=await execute('cranary',['python3','-I','-c',code]);summary['snapshot_offline_verification']=json.loads(verified['stdout'])
     # Save GitHub response bytes and decoded source using ordinary offline execution.
     dest='data-raw/cran-history/reports/2026-10-21-authorized-acquisition/downloads/rrlite-'+nonce
     payload=__import__('base64').b64encode(src['stdout'].encode()).decode()
     code=('import base64,hashlib,json; from pathlib import Path; b=base64.b64decode('+repr(payload)+'); d=json.loads(b); source=base64.b64decode(d["content"]); assert hashlib.sha256(source).hexdigest()=="015761af6d0374967c6eb563b211eab208b3b9572673176e659c74fb1d107007"; p=Path('+repr(dest)+'); f=Path(str(p)+"-source-api.json").open("xb"); f.write(b); f.close(); f=Path(str(p)+".c").open("xb"); f.write(source); f.close(); print(json.dumps({"api_path":str(p)+"-source-api.json","api_sha256":hashlib.sha256(b).hexdigest(),"source_path":str(p)+".c","source_sha256":hashlib.sha256(source).hexdigest()}))')
     saved=await execute('cranary',['python3','-I','-c',code]);summary['github_saved_receipt']=json.loads(saved['stdout'])
     denied=[('exec_run',{'workspace_id':'cranary','argv':['curl','-fsS','https://example.com/'],'network_access':True}),('exec_run',{'workspace_id':'cranary','argv':['curl','-X','POST','https://api.github.com/'],'network_access':True}),('exec_run',{'workspace_id':'cranary','argv':['curl','-L','https://api.github.com/'],'network_access':True}),('exec_run',{'workspace_id':'IRVRI','argv':['curl','-fsS','https://api.github.com/'],'network_access':True}),('exec_run',{'workspace_id':'obsidian','argv':['true'],'network_access':False}),('exec_run',{'workspace_id':'agentporter','argv':['true'],'network_access':False}),('read_file',{'workspace_id':'cranary','path':'/var/lib/agentporter-dev/config/internal-client.key'})]
     for name,args in denied:assert (await call(name,args))['is_error'],('Unexpected authority',name,args)
     code='import socket,json; s=socket.socket(); s.settimeout(2); error=s.connect_ex(("1.1.1.1",443)); s.close(); assert error!=0,"Offline sandbox unexpectedly reached public network"; print(json.dumps({"offline_network_blocked":True,"connect_errno":error}))'
     blocked=await execute('cranary',['python3','-I','-c',code]);summary['offline_network_test']=json.loads(blocked['stdout']);summary['denial_cases_passed']=len(denied)
 assert snapshots[0]['pid']==snapshots[1]['pid'];summary.update(passed=True,public_local_same_process=True,pid=snapshots[0]['pid'],fingerprint=FP);save();print(json.dumps({k:v for k,v in summary.items() if k!='calls'}),flush=True)
try:asyncio.run(main())
finally:save()
