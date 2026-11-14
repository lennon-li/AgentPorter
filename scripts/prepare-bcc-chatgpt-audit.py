#!/usr/bin/env python3
"""Overlay only this audit's source delta on the sealed BCC packages."""
import difflib
import hashlib
import json
from pathlib import Path
import shutil
import subprocess

REPO=Path(__file__).resolve().parents[1]
OUT=REPO/'artifacts/bcc-chatgpt-audit-20261113/candidate'
BASE=REPO/'artifacts/bcc-chatgpt-audit-20261113/baseline'
CHANGED=['action_policy.py','rest/routers/git.py','sandbox/workspace_transactions.py',
         'sandbox/workspace_git.py','tools/jobs.py','tooling.py','agents/development.py','sandbox/bubblewrap.py']
ADDED=['policy_errors.py','verification_runtime.py']

def sha(data):return hashlib.sha256(data).hexdigest()
def adapt(t):
 for a,b in [('codex_review','jax'),('codex_impl','liz'),('codex_research','prof')]:t=t.replace(a,b)
 return t

def main():
 OUT.mkdir(exist_ok=False)
 manifest={'roles':{}}
 for role in ('gateway','worker'):
  release=Path('/opt/agentporter-bcc/releases/consolidation-20261113-10-'+role)
  package=release/'venv/lib/python3.13/site-packages/agentporter'
  target=OUT/role/'agentporter'
  shutil.copytree(package,target,ignore=shutil.ignore_patterns('__pycache__'))
  for p in target.rglob('*'):
   if p.is_dir():p.chmod(0o755)
   elif p.is_file():p.chmod(0o644)
  target.chmod(0o755)
  for relative in CHANGED:
   name='src/agentporter/'+relative
   before=(BASE/name).read_text() if (BASE/name).exists() else subprocess.check_output(['git','show','HEAD:'+name],cwd=REPO,text=True)
   after=(REPO/name).read_text()
   patch=''.join(difflib.unified_diff(adapt(before).splitlines(True),adapt(after).splitlines(True),fromfile='a/'+relative,tofile='b/'+relative))
   result=subprocess.run(['patch','--batch','--forward','-p1'],input=patch,text=True,cwd=target,capture_output=True)
   if result.returncode:raise RuntimeError(relative+': '+result.stdout+result.stderr)
  for relative in ADDED:(target/relative).write_text(adapt((REPO/'src/agentporter'/relative).read_text()))
  files={}
  for p in target.rglob('*.py'):
   relative=p.relative_to(target);old=package/relative
   data=p.read_bytes();compile(data,str(p),'exec')
   if not old.exists() or old.read_bytes()!=data:files['agentporter/'+relative.as_posix()]={'before_sha256':sha(old.read_bytes()) if old.exists() else None,'after_sha256':sha(data)}
  assert set(files)=={'agentporter/'+n for n in CHANGED+ADDED}
  manifest['roles'][role]={'base_manifest_sha256':sha((release/'RELEASE.json').read_bytes()),'files':files}
 (OUT/'MANIFEST.json').write_text(json.dumps(manifest,indent=2,sort_keys=True)+'\n')
 print(json.dumps({'candidate':str(OUT),'manifest_sha256':sha((OUT/'MANIFEST.json').read_bytes()),'modules_per_role':len(CHANGED+ADDED)}))
if __name__=='__main__':main()
