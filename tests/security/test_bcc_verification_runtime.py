"""Sealed code-only Python supports portable tests inside the ordinary sandbox."""
import json
from pathlib import Path
import pytest
from tests.security.test_approved_git_commit import backend
from agentporter.verification_runtime import ROOT


@pytest.mark.skipif(not (ROOT/'current').exists(),reason='BCC sealed verification runtime not installed on this host')
def test_scoped_python_can_run_tests_without_host_home_or_writable_packages(tmp_path):
    root,_,sandbox,_=backend(tmp_path)
    (root/'test_scoped.py').write_text('import sys\ndef test_supported_python():\n assert sys.version_info >= (3,11)\n')
    probe="""import json,sys,pytest
from pathlib import Path
p=Path('/opt/agentporter/verification')
print(json.dumps({'supported':sys.version_info>=(3,11),'pytest':bool(pytest.__version__),
 'no_pth':not list(p.glob('lib/python3.13/site-packages/*.pth')),
 'home_hidden':not Path('/home/yeli').exists()}))
try:(p/'pyvenv.cfg').write_text('must fail')
except OSError:pass
else:raise AssertionError('Verification code is writable')
"""
    result=sandbox.run(str(root),['bcc-python','-B','-c',probe],writable=False)
    assert result['exit_code']==0,result
    assert all(json.loads(result['stdout']).values())
    result=sandbox.run(str(root),['bcc-python','-B','-m','pytest','-q','-p','no:cacheprovider','--basetemp=/tmp/scoped-tests','test_scoped.py'],writable=False)
    assert result['exit_code']==0 and '1 passed' in result['stdout'],result
