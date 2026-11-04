"""Owner-installed remote authority. Internal: does not unlock network Git.

Authority comes from a protected fixed policy, never repository configuration or
tool parameters. A future backend must separately enforce exact signatures,
supervised graph validation, admission, and durable outcome reconciliation.
"""
from dataclasses import dataclass
from contextlib import contextmanager
import hashlib
import os
from pathlib import Path, PurePosixPath
import re

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from agentporter.git_approvals import GitApprovalVerifier, _decode
from agentporter.git_policy import _read_named_policy
from agentporter.git_smart_http import RemoteRepository, ScopedGitHTTP, _ref


def _path(value):
    if (not isinstance(value, str) or not value.startswith('/') or value.startswith('//')
            or '..' in PurePosixPath(value).parts or str(PurePosixPath(value)) != value):
        raise PermissionError('Owner Git authority requires canonical absolute paths')
    return Path(value)


@dataclass(frozen=True)
class RemoteGrant:
    workspace_id: str
    remote_id: str
    repository: RemoteRepository
    ref: str
    operations: frozenset
    credential_file: object
    username: str
    repository_relative: str = '.'
    local_identity: tuple = ()


def repository_relative(value):
    """An owner-selected conventional repository inside one workspace."""
    if value == '.': return value
    if (not isinstance(value,str) or not value or len(value.encode())>1024
            or not re.fullmatch('[A-Za-z0-9._/-]{1,256}',value) or value.startswith('/') or '\\' in value or str(PurePosixPath(value))!=value
            or any(p in {'','.','..'} for p in value.split('/'))):
        raise PermissionError('Invalid exact repository location')
    from agentporter.sandbox.workspace_delta import _require_public_path
    _require_public_path(value)
    return value


@contextmanager
def selected_repository(workspace,relative='.',*,publication=False,state_dir=None):
    """Pin owner-selected child through no-follow descriptors and same mount."""
    relative=repository_relative(relative)
    root=Path(workspace).resolve(strict=True); info=root.stat()
    flags=os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC
    parent=os.open(root,flags|(os.O_PATH if info.st_uid!=os.getuid() else os.O_RDONLY))
    projection=None; descriptor=None
    try:
        pinned=os.fstat(parent)
        if (pinned.st_dev,pinned.st_ino)!=(info.st_dev,info.st_ino):raise PermissionError('Workspace root changed while pinning selection')
        if info.st_uid!=os.getuid():
            from agentporter.sandbox.workspace_projections import open_workspace_projection
            if publication:
                if state_dir is None:raise PermissionError('Publication selection requires actual private transaction state')
                from agentporter.sandbox.workspace_projections import open_workspace_publication
                projection=open_workspace_publication(parent,state_dir=state_dir)
                state_fd=os.open(state_dir,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
                try:
                    from agentporter.git_commits import _mount_id
                    if _mount_id(projection)!=_mount_id(state_fd):raise PermissionError('Publication and private transaction state cross mounts')
                finally:os.close(state_fd)
            else:projection=open_workspace_projection(parent)
        descriptor=os.dup(projection if projection is not None else parent)
        from agentporter.git_commits import _mount_id
        mount=_mount_id(descriptor)
        for part in (() if relative=='.' else relative.split('/')):
            child=os.open(part,os.O_RDONLY|flags,dir_fd=descriptor)
            os.close(descriptor);descriptor=child
            if _mount_id(descriptor)!=mount:
                raise PermissionError('Selected repository crosses workspace mount')
        yield root/relative,descriptor,info
    finally:
        if descriptor is not None:os.close(descriptor)
        if projection is not None:os.close(projection)
        os.close(parent)


def validate_clone_target(workspace,relative,*,require_empty=True):
    """Policy gate only; clone request must separately bind exact before state."""
    relative=repository_relative(relative)
    if relative=='.':raise PermissionError('Clone requires an exact child repository')
    from agentporter.git_commits import _mount_id
    with selected_repository(workspace,'.') as (_,parent,_):
        descriptor=os.dup(parent)
        try:
            mount=_mount_id(parent)
            parts=relative.split('/')
            for index,part in enumerate(parts):
                try:child=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=descriptor)
                except FileNotFoundError:return
                os.close(descriptor);descriptor=child
                if _mount_id(descriptor)!=mount:raise PermissionError('Clone target crosses workspace mount')
            if require_empty and os.listdir(descriptor):raise PermissionError('Clone target is not absent or empty')
        finally:os.close(descriptor)


class OwnerGitRemotes:
    def __init__(self, config_dir, raw, registry, verifier, grants, identities, trusted, authorization_mode='owner_signature', legacy_policy_sha256=None):
        self._config_dir = config_dir
        self._digest = hashlib.sha256(raw).digest()
        self._registry = registry
        self.verifier = verifier
        self._grants = tuple(grants)
        self._identities = identities
        self._trusted = tuple(trusted)
        self.authorization_mode=authorization_mode
        self.requires_receipt=authorization_mode!='workspace'
        self.legacy_policy_sha256=legacy_policy_sha256

    def accepts_policy_sha256(self,value,*,legacy=False):
        return value==self.policy_sha256 or (legacy and self.authorization_mode=='workspace'
            and self.legacy_policy_sha256 is not None and value==self.legacy_policy_sha256)

    @property
    def policy_sha256(self):
        return self._digest.hex()

    def catalog(self):
        """Read-only exact grant catalog; operation preconditions stay in authorize."""
        raw=_read_named_policy(self._config_dir,'git-remote-policy.json')
        if raw is None or hashlib.sha256(raw).digest()!=self._digest:
            raise PermissionError('Owner Git remote policy changed; audited restart required')
        _separation(self._registry,self._trusted)
        for workspace_id,expected in self._identities.items():
            workspace=self._registry.get(workspace_id);root=Path(workspace.path).resolve(strict=True);info=root.stat()
            if not workspace.writable or not workspace.allow_git or (str(root),info.st_dev,info.st_ino)!=expected:
                raise PermissionError('Owner Git remote workspace registration changed')
        return self._grants

    def authorize(self,workspace_id,remote_id,ref,operation,*,repository=None):
        """Authorize exact protected scope and its current operation precondition."""
        self.catalog()
        if self.authorization_mode=='workspace' and operation not in {'fetch','pull','clone'}:
            raise PermissionError('Workspace inbound policy never authorizes push')
        roots=_separation(self._registry,self._trusted)
        candidates=[g for g in self._grants if (g.workspace_id,g.remote_id,g.ref)==(workspace_id,remote_id,ref)
                    and operation in g.operations and (repository is None or g.repository_relative==repository_relative(repository))]
        if repository is None and len(candidates)>1:
            candidates=[g for g in candidates if g.repository_relative=='.']
        match=candidates[0] if len(candidates)==1 else None
        if match is None:
            raise PermissionError('Operation is outside owner Git remote policy')
        workspace = self._registry.get(workspace_id)
        root = Path(workspace.path).resolve(strict=True)
        info = root.stat()
        if (not workspace.writable or not workspace.allow_git or
                (str(root), info.st_dev, info.st_ino) != self._identities[workspace_id]):
            raise PermissionError('Owner Git remote workspace registration changed')
        if operation=='clone':
            validate_clone_target(root,match.repository_relative)
        else:
            # Per-operation signatures and pinned FDs bind current selected
            # identity. A legitimate clone does not require a policy restart.
            with selected_repository(root,match.repository_relative):pass
        # Complete current roots are supplied each time, not a startup snapshot.
        broker = ScopedGitHTTP(match.repository, credential_file=match.credential_file,
                               username=match.username, workspace_roots=roots)
        return match, broker


def _separation(registry, trusted):
    roots = [Path(entry['path']).resolve() for entry in registry.list_all()]
    for root in roots:
        if any(target == root or target.is_relative_to(root) for target in trusted):
            raise PermissionError('Owner Git remote authority overlaps an exposed workspace')
    return roots


def load_owner_git_remotes(config_dir, registry, state_dir):
    """Absent fixed policy disables authority; no network or token read occurs."""
    raw = _read_named_policy(config_dir, 'git-remote-policy.json')
    if raw is None:
        return None
    try:
        data = _decode(raw)
        if (not isinstance(data, dict) or set(data) not in ({'version', 'verification_key', 'ledger_path', 'grants'},
                {'version','verification_key','ledger_path','grants','authorization_mode'},
                {'version','verification_key','ledger_path','grants','authorization_mode','legacy_policy_sha256'})
                or type(data['version']) is not int or data['version'] != 1
                or not isinstance(data['verification_key'], str)
                or not re.fullmatch('[0-9a-f]{64}', data['verification_key'])):
            raise ValueError('schema')
        mode=data.get('authorization_mode','owner_signature')
        if mode not in {'owner_signature','workspace'}:raise ValueError('authorization mode')
        legacy=data.get('legacy_policy_sha256')
        if legacy is not None and (mode!='workspace' or not isinstance(legacy,str) or not re.fullmatch('[0-9a-f]{64}',legacy)):
            raise ValueError('legacy policy digest')
        ledger = _path(data['ledger_path'])
        entries = data['grants']
        if not isinstance(entries, list) or not 1 <= len(entries) <= 512:
            raise ValueError('grants')
        grants, seen, identities, remotes = [], set(), {}, {}
        trusted = [Path(config_dir).resolve(), ledger.resolve(), Path(state_dir).resolve(), Path(__file__).resolve().parent]
        for entry in entries:
            if not isinstance(entry, dict) or set(entry) not in ({
                    'workspace_id', 'remote_id', 'url', 'ref', 'operations', 'credential_file', 'username'},
                    {'workspace_id', 'remote_id', 'url', 'ref', 'operations', 'credential_file', 'username','repository'}):
                raise ValueError('grant schema')
            for field in ('workspace_id', 'remote_id'):
                if not isinstance(entry[field], str) or not re.fullmatch('[A-Za-z0-9_-]{1,128}', entry[field]):
                    raise ValueError('identifier')
            if not _ref(entry['ref'], branch=True):
                raise ValueError('branch')
            operations = entry['operations']
            if mode=='workspace' and 'push' in operations:
                raise PermissionError('Workspace inbound policy cannot grant push')
            if (not isinstance(operations, list) or not operations or
                    any(not isinstance(op, str) or op not in {'fetch', 'pull', 'push', 'clone'} for op in operations)
                    or len(set(operations)) != len(operations)):
                raise ValueError('operations')
            relative=repository_relative(entry.get('repository','.'))
            identity = (entry['workspace_id'], relative, entry['remote_id'], entry['ref'])
            if identity in seen:
                raise ValueError('duplicate grant')
            seen.add(identity)
            repository = RemoteRepository(entry['url'])
            credential = None if entry['credential_file'] is None else _path(entry['credential_file'])
            # Validate fixed username/dependencies without accessing credentials.
            ScopedGitHTTP(repository, credential_file=credential, username=entry['username'])
            remote_key = (entry['workspace_id'], relative, entry['remote_id'])
            endpoint = (repository.url, credential, entry['username'])
            if remote_key in remotes and remotes[remote_key] != endpoint:
                raise ValueError('inconsistent remote identity')
            remotes[remote_key] = endpoint
            if credential is not None:
                trusted.append(credential.resolve())
            workspace = registry.get(entry['workspace_id'])
            if not workspace.writable or not workspace.allow_git:
                raise ValueError('workspace permissions')
            root = Path(workspace.path).resolve(strict=True)
            info = root.stat()
            identities[entry['workspace_id']] = (str(root), info.st_dev, info.st_ino)
            relative=repository_relative(entry.get('repository','.'))
            if 'clone' in operations:
                validate_clone_target(root,relative,require_empty=False)
            else:
                with selected_repository(root,relative):pass
            if relative!='.' and 'push' in operations:
                raise PermissionError('Nested push is outside the supported exact backend')
            local_identity=identities[entry['workspace_id']]
            grants.append(RemoteGrant(entry['workspace_id'], entry['remote_id'], repository,
                entry['ref'], frozenset(operations), credential, entry['username'],relative,local_identity))
        _separation(registry, trusted)
        verifier = GitApprovalVerifier(Ed25519PublicKey.from_public_bytes(bytes.fromhex(data['verification_key'])),
                                       ledger, existing_only=True)
        return OwnerGitRemotes(config_dir, raw, registry, verifier, grants, identities, trusted,mode,legacy)
    except (ValueError, TypeError, KeyError, AttributeError):
        raise PermissionError('Invalid owner Git remote policy') from None
