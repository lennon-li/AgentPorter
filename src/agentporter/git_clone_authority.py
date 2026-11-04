"""Exact consumed clone birth authority; protected owner policy remains mandatory."""
from dataclasses import dataclass
import base64,json,re,hashlib
from pathlib import Path
from cryptography.exceptions import InvalidSignature
from agentporter.git_approvals import GitApprovalRequest,_canonical,_decode,_AUDIENCE,_APPROVAL_DOMAIN
from agentporter.git_remote_policy import load_owner_git_remotes
from agentporter.git_clone_preparation import CloneScope


def validate_clone_authorization(document,*,registry,state_dir,owner_config_dir,require_consumed=True):
    try:
        fields={'version','request','request_sha256','approval_nonce','approval_receipt','verification_context'}
        local=isinstance(document,dict) and document.get('version')==2 and document.get('authorization_mode')=='workspace'
        if local:fields=fields|{'authorization_mode'}
        if not isinstance(document,dict) or set(document)!=fields or document['version']!=(2 if local else 1):raise ValueError('schema')
        authority=load_owner_git_remotes(owner_config_dir,registry,state_dir)
        if authority is None:raise ValueError('protected owner policy absent')
        verifier=authority.verifier
        policy_digest=document['verification_context']['policy_sha256']
        if not authority.accepts_policy_sha256(policy_digest,legacy=not local):raise ValueError('policy digest changed')
        context={'owner_config_dir':str(Path(owner_config_dir).resolve(strict=True)),'policy_sha256':policy_digest,
            'ledger_path':str(verifier.ledger_path),'ledger_identity':list(verifier._ledger_identity),'ledger_parent_identity':list(verifier._parent_identity)}
        if document['verification_context']!=context:raise ValueError('protected verification context changed')
        request=GitApprovalRequest.from_payload(document['request']);p=request.to_payload();v=p['parameters']
        fields={'identity_kind','repository','target_before','private_candidate','remote_id','remote_url','remote_ref','remote_oid','object_format','tracking_ref','local_branch','pack_sha256','pack_size','policy_sha256','job_context'}
        if p['operation']!='clone' or p['expected_head']is not None or document['request_sha256']!=request.digest or set(v)!=fields or v['identity_kind']!='parent_workspace' or v['policy_sha256']!=policy_digest:raise ValueError('exact clone request')
        scope=CloneScope(p['workspace_id'],p['repository_path'],v['repository'],v['remote_id'],v['remote_url'],v['remote_ref'],v['local_branch'],v['policy_sha256'])
        width={'sha1':40,'sha256':64}.get(v['object_format'],0)
        if not width or not re.fullmatch('[0-9a-f]{'+str(width)+'}',v['remote_oid']) or set(v['remote_oid'])=={'0'} or p['expected_tree']!=hashlib.new(v['object_format'],b'tree 0\0').hexdigest() or p['branch']!=v['local_branch']:raise ValueError('clone graph')
        if v['tracking_ref']!='refs/remotes/'+v['remote_id']+'/'+v['remote_ref'].removeprefix('refs/heads/') or not re.fullmatch('[0-9a-f]{64}',v['pack_sha256']) or type(v['pack_size'])is not int or not 1<=v['pack_size']<=64*1024*1024-65520:raise ValueError('clone acquisition')
        workspace=registry.get(p['workspace_id']);root=Path(workspace.path).resolve(strict=True);info=root.stat()
        if not workspace.allow_git or not workspace.writable or (str(root),info.st_dev,info.st_ino)!=(p['repository_path'],p['repository_device'],p['repository_inode']):raise ValueError('canonical parent workspace changed')
        # Clone may now be populated. Revalidate fixed policy and grant without
        # mistaking the consumed operation for a second clone precondition.
        grants=[g for g in authority._grants if (g.workspace_id,g.remote_id,g.ref,g.repository_relative)==(p['workspace_id'],v['remote_id'],v['remote_ref'],v['repository']) and 'clone'in g.operations]
        if len(grants)!=1 or grants[0].repository.url!=v['remote_url']:raise ValueError('fixed owner clone grant changed')
        if local:
            if document['approval_receipt']!='':raise ValueError('Workspace clone cannot contain an external receipt')
            from agentporter.git_authorizations import validate_workspace_request,assert_claim
            validate_workspace_request(authority,request)
            if not isinstance(document['approval_nonce'],str) or not re.fullmatch('[0-9a-f]{32}',document['approval_nonce']):raise ValueError('server nonce')
            if require_consumed:assert_claim(authority,request,document['approval_nonce'])
            return request
        if not isinstance(document['approval_receipt'],str) or not document['approval_receipt'].isascii() or len(document['approval_receipt'])>8192:raise ValueError('bounded receipt')
        receipt=_decode(document['approval_receipt'])
        if set(receipt)!={'claims','signature'}:raise ValueError('receipt envelope')
        claims=receipt['claims'];encoded=receipt['signature']
        if set(claims)!={'version','audience','nonce','issued_at','expires_at','request_sha256'} or claims['version']!=1 or claims['audience']!=_AUDIENCE or claims['request_sha256']!=request.digest or claims['nonce']!=document['approval_nonce'] or not re.fullmatch('[0-9a-f]{32}',claims['nonce']) or type(claims['issued_at'])is not int or type(claims['expires_at'])is not int or claims['issued_at']<0 or not 1<=claims['expires_at']-claims['issued_at']<=300 or not re.fullmatch('[A-Za-z0-9_-]{86}',encoded):raise ValueError('receipt claims')
        signature=base64.urlsafe_b64decode(encoded+'==')
        if base64.urlsafe_b64encode(signature).rstrip(b'=').decode()!=encoded:raise ValueError('signature encoding')
        verifier.public_key.verify(signature,_APPROVAL_DOMAIN+_canonical(claims))
        if require_consumed:verifier.assert_consumed(document['approval_nonce'],request)
        return request
    except (ValueError,TypeError,KeyError,AttributeError,InvalidSignature) as error:raise PermissionError('Clone birth lacks exact consumed owner authority') from error


@dataclass(frozen=True)
class CloneBirthAuthorization:
    backend:object
    transaction:object
    document_json:bytes

    @property
    def document(self):return _decode(self.document_json)
    def validate(self):
        request=validate_clone_authorization(self.document,registry=self.backend.registry,state_dir=self.backend.sandbox.state_dir,owner_config_dir=self.backend.authority._config_dir)
        self.backend._validate_job(request,allow_finalizing=True)
        if self.transaction is not self.backend.manager._job_transactions.get(request.to_payload()['parameters']['job_context']['job_id']):raise PermissionError('Clone birth lost exact parent transaction')
        return request.to_payload()['parameters']
