"""Owner-installed remote authority. Internal: does not unlock network Git.

Authority comes from a protected fixed policy, never repository configuration or
tool parameters. A future backend must separately enforce exact signatures,
supervised graph validation, admission, and durable outcome reconciliation.
"""
from dataclasses import dataclass
import hashlib
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


class OwnerGitRemotes:
    def __init__(self, config_dir, raw, registry, verifier, grants, identities, trusted):
        self._config_dir = config_dir
        self._digest = hashlib.sha256(raw).digest()
        self._registry = registry
        self.verifier = verifier
        self._grants = tuple(grants)
        self._identities = identities
        self._trusted = tuple(trusted)

    @property
    def policy_sha256(self):
        return self._digest.hex()

    def authorize(self, workspace_id, remote_id, ref, operation):
        """Return fixed authority only after revalidating the complete catalog."""
        raw = _read_named_policy(self._config_dir, 'git-remote-policy.json')
        if raw is None or hashlib.sha256(raw).digest() != self._digest:
            raise PermissionError('Owner Git remote policy changed; audited restart required')
        roots = _separation(self._registry, self._trusted)
        match = next((g for g in self._grants if (g.workspace_id, g.remote_id, g.ref) ==
                      (workspace_id, remote_id, ref) and operation in g.operations), None)
        if match is None:
            raise PermissionError('Operation is outside owner Git remote policy')
        workspace = self._registry.get(workspace_id)
        root = Path(workspace.path).resolve(strict=True)
        info = root.stat()
        if (not workspace.writable or not workspace.allow_git or
                (str(root), info.st_dev, info.st_ino) != self._identities[workspace_id]):
            raise PermissionError('Owner Git remote workspace registration changed')
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
        if (not isinstance(data, dict) or set(data) != {'version', 'verification_key', 'ledger_path', 'grants'}
                or type(data['version']) is not int or data['version'] != 1
                or not isinstance(data['verification_key'], str)
                or not re.fullmatch('[0-9a-f]{64}', data['verification_key'])):
            raise ValueError('schema')
        ledger = _path(data['ledger_path'])
        entries = data['grants']
        if not isinstance(entries, list) or not 1 <= len(entries) <= 128:
            raise ValueError('grants')
        grants, seen, identities, remotes = [], set(), {}, {}
        trusted = [Path(config_dir).resolve(), ledger.resolve(), Path(state_dir).resolve(), Path(__file__).resolve().parent]
        for entry in entries:
            if not isinstance(entry, dict) or set(entry) != {
                    'workspace_id', 'remote_id', 'url', 'ref', 'operations', 'credential_file', 'username'}:
                raise ValueError('grant schema')
            for field in ('workspace_id', 'remote_id'):
                if not isinstance(entry[field], str) or not re.fullmatch('[A-Za-z0-9_-]{1,128}', entry[field]):
                    raise ValueError('identifier')
            if not _ref(entry['ref'], branch=True):
                raise ValueError('branch')
            operations = entry['operations']
            if (not isinstance(operations, list) or not operations or
                    any(not isinstance(op, str) or op not in {'fetch', 'push'} for op in operations)
                    or len(set(operations)) != len(operations)):
                raise ValueError('operations')
            identity = (entry['workspace_id'], entry['remote_id'], entry['ref'])
            if identity in seen:
                raise ValueError('duplicate grant')
            seen.add(identity)
            repository = RemoteRepository(entry['url'])
            credential = None if entry['credential_file'] is None else _path(entry['credential_file'])
            # Validate fixed username/dependencies without accessing credentials.
            ScopedGitHTTP(repository, credential_file=credential, username=entry['username'])
            remote_key = (entry['workspace_id'], entry['remote_id'])
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
            grants.append(RemoteGrant(entry['workspace_id'], entry['remote_id'], repository,
                entry['ref'], frozenset(operations), credential, entry['username']))
        _separation(registry, trusted)
        verifier = GitApprovalVerifier(Ed25519PublicKey.from_public_bytes(bytes.fromhex(data['verification_key'])),
                                       ledger, existing_only=True)
        return OwnerGitRemotes(config_dir, raw, registry, verifier, grants, identities, trusted)
    except (ValueError, TypeError, KeyError, AttributeError):
        raise PermissionError('Invalid owner Git remote policy') from None
