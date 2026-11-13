#!/usr/bin/env python3
"""Prepare only the tested provider-custody delta on sealed BCC generation 06."""
import hashlib,json
from pathlib import Path
REPO=Path('/home/yeli/repos/AgentPorter')
OUT=REPO/'artifacts/bcc-consolidation-20261112/provider-custody-v07'
SITE=Path('venv/lib/python3.13/site-packages')
def sha(raw):return hashlib.sha256(raw).hexdigest()
def once(raw,before,after):
 assert raw.count(before)==1,(before[:120],raw.count(before))
 return raw.replace(before,after)
def main():
 OUT.mkdir(exist_ok=False)
 manifest={'schema':1,'roles':{}}
 for role in ('gateway','worker'):
  root=Path('/opt/agentporter-bcc/releases/consolidation-20261113-06-'+role)
  files={}
  def save(relative,after):
   before=(root/SITE/relative).read_bytes();target=OUT/role/relative;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(after)
   files[relative]={'before_sha256':sha(before),'after_sha256':sha(after)}
  save('agentporter/agents/credential_broker.py',(REPO/'src/agentporter/agents/credential_broker.py').read_bytes())
  raw=(root/SITE/'agentporter/agents/development.py').read_text()
  raw=once(raw,'if not isinstance(credentials, dict) or not credentials:',"if not isinstance(credentials, dict) or (not credentials and spec.get('credential_broker') is None):")
  source=(REPO/'src/agentporter/agents/development.py').read_text()
  start=source.index("            providers={'codex_review'")
  end=source.index('        canonical_credentials = {}',start)
  replacement=source[start:end]
  for before,after in [('codex_review','jax'),('codex_impl','liz'),('codex_research','prof'),('claude_agent','ming'),('copilot_agent','phil'),('.copilot-agent/','.copilot-phil/')]:replacement=replacement.replace(before,after)
  start=raw.index("            if (agent not in {'jax', 'liz', 'prof'}")
  end=raw.index('        canonical_credentials = {}',start)
  raw=raw[:start]+replacement+raw[end:]
  start=source.index("                destination={'codex':'.codex/auth.json'")
  end=source.index('            if agent in ',start)
  replacement=source[start:end].replace('.copilot-agent/','.copilot-phil/')
  before="                credential_lease = BrokerCredentialLease(spec['credential_broker'], home/'.codex/auth.json')\n"
  raw=once(raw,before,replacement)
  compile(raw,'development.py','exec')
  save('agentporter/agents/development.py',raw.encode())
  manifest['roles'][role]={'base_manifest_sha256':sha((root/'RELEASE.json').read_bytes()),'files':files}
 p=OUT/'MANIFEST.json';p.write_text(json.dumps(manifest,sort_keys=True,indent=2)+'\n');print(json.dumps({'candidate':str(OUT),'manifest_sha256':sha(p.read_bytes())}))
if __name__=='__main__':main()
