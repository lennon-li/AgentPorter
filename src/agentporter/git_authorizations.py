"""Server-local inbound operation claims, reusing the commit ledger format.

Protected workspace/remote policy supplies authority. These are durable operation
IDs, never owner signatures or caller-provided bearer authorization.
"""
import secrets
import sqlite3
import time
from dataclasses import dataclass

from agentporter.git_approvals import VerifiedGitApproval

INBOUND = frozenset({'fetch', 'pull', 'clone'})


def workspace_mode(authority):
    return getattr(authority, 'authorization_mode', 'owner_signature') == 'workspace'


def validate_workspace_request(authority, request):
    """Rebind the complete protected scope without replaying target preconditions."""
    if not workspace_mode(authority):
        raise PermissionError('Workspace Git authorization is not enabled by protected policy')
    p=request.to_payload();v=p['parameters']
    if p['operation'] not in INBOUND or v.get('policy_sha256') != authority.policy_sha256:
        raise PermissionError('Workspace Git request operation or policy differs')
    from pathlib import Path
    from agentporter.git_remote_policy import repository_relative,selected_repository
    relative=repository_relative(v.get('repository' if p['operation']=='clone' else 'repository_relative','.'))
    grants=[g for g in authority.catalog() if
        (g.workspace_id,g.repository_relative,g.remote_id,g.ref)==
        (p['workspace_id'],relative,v.get('remote_id'),v.get('remote_ref'))
        and p['operation'] in g.operations and g.repository.url==v.get('remote_url')]
    if len(grants)!=1:
        raise PermissionError('Workspace Git request is outside exact protected grant')
    root=Path(authority._registry.get(p['workspace_id']).path).resolve(strict=True)
    expected=root if p['operation']=='clone' else root/relative
    if p['repository_path'] != str(expected):
        raise PermissionError('Workspace Git request canonical repository differs')
    root_info=root.stat()
    if p['operation']=='clone':
        actual=root_info
    else:
        with selected_repository(root,relative) as (_,descriptor,_):
            import os
            actual=os.fstat(descriptor)
    if (p['repository_device'],p['repository_inode'])!=(actual.st_dev,actual.st_ino):
        raise PermissionError('Workspace Git request selected directory identity differs')
    if relative!='.' and p['operation']!='clone' and v.get('workspace_identity')!={
            'path':str(root),'device':root_info.st_dev,'inode':root_info.st_ino}:
        raise PermissionError('Workspace Git request parent identity differs')


def local_nonce():
    return secrets.token_hex(16)


def claim(authority, request, receipt='', *, nonce=None):
    """Claim a locked server-built request; blank receipts are not a global bypass."""
    if not workspace_mode(authority):
        return authority.verifier.verify_and_consume(receipt,request)
    if receipt:
        raise ValueError('Workspace inbound Git does not accept external approval receipts')
    validate_workspace_request(authority,request)
    import re
    nonce=local_nonce() if nonce is None else nonce
    if not isinstance(nonce,str) or not re.fullmatch('[0-9a-f]{32}',nonce):
        raise PermissionError('Invalid server operation nonce')
    verifier=authority.verifier;verifier._check_ledger_identity()
    try:
        with sqlite3.connect(verifier.ledger_path,timeout=5) as db:
            db.execute('PRAGMA synchronous=FULL');db.execute('BEGIN IMMEDIATE')
            verifier._check_ledger_identity()
            validate_workspace_request(authority,request)
            db.execute('INSERT INTO consumed VALUES (?,?,?,?)',(nonce,request.digest,int(time.time()),0))
    except sqlite3.IntegrityError as error:
        raise PermissionError('Workspace Git operation already claimed') from error
    return VerifiedGitApproval(request.digest,nonce,0)


def assert_claim(authority, request, nonce):
    """Recovery accepts only the exact durable local claim, not an empty receipt."""
    validate_workspace_request(authority,request)
    authority.verifier.assert_consumed(nonce,request)
    from urllib.parse import quote
    with sqlite3.connect('file:'+quote(str(authority.verifier.ledger_path))+'?mode=ro',uri=True) as db:
        row=db.execute('SELECT request_sha256,expires_at FROM consumed WHERE nonce=?',(nonce,)).fetchone()
    if row!=(request.digest,0):
        raise PermissionError('Workspace Git guard does not name a durable local operation claim')


def workspace_policy_document(data, *, previous_raw=None):
    """Data-only activation proposal; never edits config or resets old ledgers."""
    from copy import deepcopy
    if any('push' in g['operations'] for g in data['grants']):
        raise PermissionError('Agent policy must never grant push')
    result=deepcopy(data);result['authorization_mode']='workspace'
    if previous_raw is not None:
        import hashlib
        result['legacy_policy_sha256']=hashlib.sha256(previous_raw).hexdigest()
    return result
