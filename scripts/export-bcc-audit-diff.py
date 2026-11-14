#!/usr/bin/env python3
"""Export only this audit's delta, preserving the initial dirty checkout."""
import difflib,hashlib,json,os,re,subprocess
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
OUT=ROOT/'artifacts/bcc-chatgpt-audit-20261113'
def main():
 initial=json.loads((OUT/'baseline-manifest.json').read_text())
 def git(*args):return subprocess.check_output(['git',*args],cwd=ROOT,env=dict(os.environ,GIT_OPTIONAL_LOCKS='0'))
 current=set(git('diff','--name-only','-z').decode().rstrip('\0').split('\0'))|set(git('ls-files','--others','--exclude-standard','-z').decode().rstrip('\0').split('\0'))
 changed=[];chunks=[];untouched=0
 for name in sorted(current):
  if not name:continue
  path=ROOT/name;backup=OUT/'baseline'/name
  if name in initial:
   if not backup.exists():
    assert name.startswith('.trash/') and hashlib.sha256(path.read_bytes()).hexdigest()==initial[name]['sha256'];untouched+=1;continue
   before=backup.read_bytes()
  else:
   result=subprocess.run(['git','show','HEAD:'+name],cwd=ROOT,capture_output=True);before=result.stdout if result.returncode==0 else b''
  after=path.read_bytes()
  if before==after:
   if name in initial:
    i=path.stat();assert i.st_uid==initial[name]['uid'] and i.st_gid==initial[name]['gid'] and i.st_mode&0o777==initial[name]['mode'];untouched+=1
   continue
  changed.append(name)
  chunks.extend(difflib.unified_diff(before.decode().splitlines(True),after.decode().splitlines(True),fromfile='a/'+name if before else '/dev/null',tofile='b/'+name))
 text=''.join(chunks)
 for pattern in (r'sk-ant-[A-Za-z0-9_-]{40,}',r'gh[pousr]_[A-Za-z0-9]{30,}',r'github_pat_[A-Za-z0-9_]{50,}',r'eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{20,}',r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----'):
  assert re.search(pattern,text) is None,'Potential credential in review diff; do not print it'
 (OUT/'repair.diff').write_text(text);(OUT/'changed-paths.json').write_text(json.dumps(changed,indent=2)+'\n')
 result={'audit_changed_files':len(changed),'preexisting_dirty_files_unchanged':untouched,'trash_preserved':True,'diff_sha256':hashlib.sha256(text.encode()).hexdigest(),'diff_bytes':len(text.encode()),'branch':git('branch','--show-current').decode().strip(),'head':git('rev-parse','HEAD').decode().strip(),'index_clean':not git('diff','--cached','--name-only').strip()}
 assert result['branch']=='main' and result['head']=='ef78f5a8f2932e30cfcd545e6d670c45a5d40e77' and result['index_clean']
 (OUT/'final-source-preservation.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result))
if __name__=='__main__':main()
