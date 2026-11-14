#!/usr/bin/env python3
"""Reproducible focused suite with explicit counts; no native credentials or models."""
import argparse,json,os
from pathlib import Path
import pytest
SELECTED=['tests/security/test_bcc_consolidation.py','tests/security/test_bcc_qman_contract.py',
 'tests/security/test_shared_cli.py','tests/security/test_credential_broker.py','tests/security/test_credential_lease.py',
 'tests/security/test_git_commit_policy.py','tests/security/test_git_approval_receipts.py',
 'tests/security/test_action_matrix.py','tests/security/test_development_runtime.py',
 'tests/security/test_worker_git_runtime.py','tests/security/test_provider_origin_broker.py',
 'tests/unit/test_execution_policy.py','tests/unit/test_operator_action_policy.py','tests/unit/test_tool_publication_parity.py',
 'tests/security/test_bcc_git_views.py','tests/security/test_git_metadata_scope.py','tests/security/test_copilot_account_fields.py','tests/security/test_bcc_policy_diagnostics.py','tests/security/test_bcc_verification_runtime.py','tests/unit/test_bcc_dispatch_contract.py',
 'tests/unit/test_bcc_astra_rollout.py']
class Counts:
 def __init__(self):self.collected=0;self.values={'passed':0,'failed':0,'skipped':0,'errors':0}
 def pytest_collection_finish(self,session):self.collected=len(session.items)
 def pytest_runtest_logreport(self,report):
  if report.when=='call':self.values['passed' if report.passed else 'skipped' if report.skipped else 'failed']+=1
  elif report.failed:self.values['errors']+=1
  elif report.skipped:self.values['skipped']+=1
 def pytest_collectreport(self,report):
  if report.failed:self.values['errors']+=1
  elif report.skipped:self.values['skipped']+=1
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--receipt',required=True);p.add_argument('--basetemp',required=True);a=p.parse_args()
 counts=Counts();code=pytest.main(['-q','-p','no:cacheprovider','--tb=short','--basetemp='+a.basetemp,*SELECTED],plugins=[counts])
 value={'collected':counts.collected,**counts.values,'exit_code':int(code),'native_sandbox':bool(os.getenv('AGENTPORTER_TEST_BWRAP'))}
 Path(a.receipt).write_text(json.dumps(value,indent=2)+'\n');print(json.dumps(value));raise SystemExit(code)
