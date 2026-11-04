import json
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from agentporter.git_approvals import GitApprovalRequest,GitApprovalVerifier
from tests.security.test_owner_approval_protocol import run
from tests.security.test_clone_service import setup_clone
from tests.security.test_development_runtime import runtime_factory

@pytest.mark.parametrize('existing',[False,True])
def test_native_clone_owner_browser_receipt(tmp_path,monkeypatch,runtime_factory,existing):
 root,service,key,manager,tx,bound,request=setup_clone(tmp_path,monkeypatch,runtime_factory,existing=existing)
 try:
  reply=run(json.dumps({'request':request.to_payload(),'request_sha256':request.digest}))
  assert reply['ok'],reply
  assert reply['payload'].encode()==request.canonical_payload and reply['privateExportDenied'] and reply['frozen']
  verifier=GitApprovalVerifier(Ed25519PublicKey.from_public_bytes(bytes.fromhex(reply['publicKey'])),tmp_path/'browser/claims.db')
  verifier.verify_and_consume(reply['receipt'],request,now=1002)
 finally:manager.cancel(bound.job_id)

@pytest.mark.parametrize('field,value',[('identity_kind','repository'),('repository','../escape'),('target_before',{'kind':'present'}),('tracking_ref','refs/remotes/other/main'),('remote_url','https://token@example.com/owner/repo.git'),('local_branch','refs/heads/*'),('pack_size',0)])
def test_owner_browser_refuses_expanded_clone_request(tmp_path,monkeypatch,runtime_factory,field,value):
 root,service,key,manager,tx,bound,request=setup_clone(tmp_path,monkeypatch,runtime_factory)
 try:
  payload=request.to_payload();payload['parameters'][field]=value;changed=GitApprovalRequest.from_payload(payload)
  reply=run(json.dumps({'request':payload,'request_sha256':changed.digest}))
  assert not reply['ok'] and 'receipt'not in reply and 'publicKey'not in reply
 finally:manager.cancel(bound.job_id)


def test_clone_browser_refuses_nonempty_tree_baseline(tmp_path,monkeypatch,runtime_factory):
 root,service,key,manager,tx,bound,request=setup_clone(tmp_path,monkeypatch,runtime_factory)
 try:
  payload=request.to_payload();payload['expected_tree']='a'*40;changed=GitApprovalRequest.from_payload(payload)
  reply=run(json.dumps({'request':payload,'request_sha256':changed.digest}))
  assert not reply['ok'] and 'receipt'not in reply
 finally:manager.cancel(bound.job_id)
