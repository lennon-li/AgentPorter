#!/usr/bin/env python3
"""Run inside an ordinary/Jax sandbox. No native auth reads or network requests."""
import argparse,hashlib,json,os
from pathlib import Path
import subprocess,sys,tempfile,time,xml.etree.ElementTree as ET
PORTABLE=['tests/security/test_shared_cli.py','tests/security/test_credential_lease.py',
 'tests/unit/test_execution_policy.py','tests/unit/test_operator_action_policy.py',
 'tests/unit/test_tool_publication_parity.py','tests/unit/test_bcc_dispatch_contract.py',
 'tests/security/test_bcc_policy_diagnostics.py']

def git(*args):
 return subprocess.run(['/usr/bin/git','-c','safe.directory=/workspace',*args],cwd='/workspace',capture_output=True,check=True).stdout

def main():
 p=argparse.ArgumentParser();p.add_argument('--expected-head-inode',type=int,required=True);p.add_argument('--expected-refs-sha256',required=True);p.add_argument('--receipt');a=p.parse_args()
 root=Path('/workspace/.git');head=git('rev-parse','HEAD').decode().strip()
 result={'observed_epoch':time.time(),'python':sys.version.split()[0],
  'supported_python':sys.version_info>=(3,11),'git_head_readable':(root/'HEAD').is_file(),
  'git_objects_exists':(root/'objects').is_dir(),'real_history_object_readable':git('cat-file','-t',head).strip()==b'commit',
  'git_metadata_inode_is_private':(root/'HEAD').stat().st_ino!=a.expected_head_inode,
  'canonical_refs_match':hashlib.sha256(git('for-each-ref','--format=%(refname)%00%(objectname)%00%(symref)')).hexdigest()==a.expected_refs_sha256,
  'host_hooks_absent':not(root/'hooks').exists(),'host_worktrees_absent':not(root/'worktrees').exists(),
  'alternates_absent':not(root/'objects/info/alternates').exists(),
  'host_home_absent':not Path('/home/yeli').exists(),
  'credential_socket_absent':not Path('/run/agentporter-bcc-auth/auth.sock').exists(),
  'hooks_disabled':git('config','core.hooksPath').strip()==b'/dev/null',
  'native_store_reads':False,'model_calls_from_probe':0,
  'native_launch_fixtures_run':False}
 with tempfile.TemporaryDirectory(prefix='bcc-portable-') as temp:
  receipt=Path(temp)/'tests.xml'
  cmd=[sys.executable,'-B','-m','pytest','-q','-p','no:cacheprovider','--basetemp='+str(Path(temp)/'state'),'--junitxml='+str(receipt),'-k','not runtime and not explicit_same_account_alias_uses_one_canonical_store',*PORTABLE]
  r=subprocess.run(cmd,cwd='/workspace',capture_output=True,text=True,timeout=120)
  suites=ET.parse(receipt).getroot();rows=list(suites) if suites.tag=='testsuites' else [suites]
  counts={k:sum(int(row.get(k,0)) for row in rows) for k in ('tests','failures','errors','skipped')}
  counts['passed']=counts['tests']-counts['failures']-counts['errors']-counts['skipped'];counts['exit_code']=r.returncode
  result['portable_tests']=counts
  if r.returncode:result['failed_cases']=[e.get('name') for e in suites.iter('testcase') if e.find('failure') is not None or e.find('error') is not None]
 result['passed']=all(value for key,value in result.items() if key.endswith(('_absent','_readable','_private','_match','_disabled')) or key=='supported_python') and result['portable_tests']['exit_code']==0
 if a.receipt:
  target=Path(a.receipt)
  assert not target.is_absolute() and '..' not in target.parts and target.as_posix().startswith('artifacts/bcc-chatgpt-audit-20261113/')
  target.write_text(json.dumps(result,indent=2)+'\n')
 print(json.dumps(result,sort_keys=True));return 0 if result['passed'] else 1
if __name__=='__main__':raise SystemExit(main())
