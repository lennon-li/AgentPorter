"""Bounded exact grants for seven agents ×26projects ×two disposable selectors."""
import json
from pathlib import Path
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding,PublicFormat
from agentporter.git_approvals import GitApprovalVerifier
from agentporter.git_remote_policy import load_owner_git_remotes
from agentporter.git_policy import _read_named_policy
from agentporter.workspaces.registry import WorkspaceRegistry

@pytest.fixture
def batch(tmp_path):
 config=tmp_path/'config';config.mkdir(mode=0o700);state=tmp_path/'state';state.mkdir(mode=0o700)
 key=Ed25519PrivateKey.generate();ledger=config/'claims.db';GitApprovalVerifier(key.public_key(),ledger)
 registry=WorkspaceRegistry({});grants=[]
 for number in range(26):
  root=tmp_path/('canonical-project-'+str(number));root.mkdir()
  project='project-'+str(number);registry.register(project,str(root),writable=True,allow_git=True)
  for agent in ('codex_review','codex_impl','codex_research','copilot_agent','opencode_free','claude_agent','agy_agent'):
   inbound=f'git-acceptance/{agent}/inbound';(root/inbound).mkdir(parents=True)
   for relative,ops in ((inbound,['fetch','pull']),(f'git-acceptance/{agent}/clone',['clone'])):
    grants.append({'workspace_id':project,'repository':relative,'remote_id':'origin','url':'https://example.com/owner/repo.git','ref':'refs/heads/main','operations':ops,'credential_file':None,'username':'owner'})
 document={'version':1,'verification_key':key.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw).hex(),'ledger_path':str(ledger),'grants':grants}
 path=config/'git-remote-policy.json'
 def write(value):path.write_text(json.dumps(value));path.chmod(0o600)
 write(document)
 return config,state,registry,document,path,write


def test_complete364_exact_grants_fit_only_remote_policy_budget(batch):
 config,state,registry,document,path,write=batch
 assert len(document['grants'])==364 and 65536<path.stat().st_size<256*1024
 authority=load_owner_git_remotes(config,registry,state)
 assert len(authority.catalog())==364
 assert {g.workspace_id for g in authority.catalog()}=={'project-'+str(i) for i in range(26)}
 selected,_=authority.authorize('project-12','origin','refs/heads/main','pull',repository='git-acceptance/codex_research/inbound')
 assert selected.repository_relative=='git-acceptance/codex_research/inbound'
 with pytest.raises(PermissionError):authority.authorize('project-12','origin','refs/heads/main','clone',repository='git-acceptance/codex_research/inbound')
 with pytest.raises(PermissionError):authority.authorize('project-12','origin','refs/heads/main','pull',repository='git-acceptance/not-granted/inbound')


def test512_is_bounded_and513_is_refused(batch):
 config,state,registry,document,path,write=batch
 for index in range(149):document['grants'].append({**document['grants'][1],'repository':'overflow-'+str(index)})
 extra=document['grants'].pop();assert len(document['grants'])==512
 write(document);assert len(load_owner_git_remotes(config,registry,state).catalog())==512
 document['grants'].append(extra);write(document)
 with pytest.raises(PermissionError,match='Invalid owner Git remote policy'):load_owner_git_remotes(config,registry,state)


def test_remote256KiB_limit_does_not_raise_other_named_policy_limits(batch):
 config,state,registry,document,path,write=batch
 raw=path.read_bytes();path.write_bytes(raw+b' '*(256*1024-len(raw)))
 assert len(load_owner_git_remotes(config,registry,state).catalog())==364
 path.write_bytes(path.read_bytes()+b' ')
 with pytest.raises(PermissionError):load_owner_git_remotes(config,registry,state)
 commit=config/'git-commit-policy.json';commit.write_bytes(b' '*(65536+1));commit.chmod(0o600)
 with pytest.raises(PermissionError):_read_named_policy(config,'git-commit-policy.json')
