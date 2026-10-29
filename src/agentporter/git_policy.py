"""Optional owner-installed authority for exact approved Git commits."""
import hashlib
import os
from pathlib import Path, PurePosixPath
import re
import stat

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from agentporter.git_approvals import GitApprovalVerifier, _decode
from agentporter.git_commits import ApprovedGitCommits
from agentporter.scoped_https import ScopedPublicHTTPSPolicy


def _read_policy(config_dir):
    return _read_named_policy(config_dir, 'git-commit-policy.json')


def _read_named_policy(config_dir, name):
    """Read a fixed backend-selected policy, never a caller-selected path."""
    if name not in {'git-commit-policy.json', 'git-remote-policy.json'}:
        raise ValueError('Unknown owner Git policy')
    directory = ScopedPublicHTTPSPolicy._open_trusted_directory(Path(config_dir).absolute())
    if directory is None:
        return None
    try:
        try:
            descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                                 dir_fd=directory)
        except FileNotFoundError:
            return None
        try:
            info = os.fstat(descriptor)
            if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid not in {0, os.getuid()}
                    or info.st_mode & 0o022 or (info.st_uid != 0 and info.st_mode & 0o077)
                    or info.st_size > 65536):
                raise PermissionError('Untrusted owner Git policy')
            with os.fdopen(descriptor, 'rb', closefd=False) as stream:
                raw = stream.read(65537)
            if len(raw) > 65536:
                raise PermissionError('Owner Git policy exceeds size limit')
            return raw
        finally:
            os.close(descriptor)
    finally:
        os.close(directory)


class _PolicyCommits:
    def __init__(self, backend, config_dir, policy_bytes, workspaces, trusted):
        self.backend = backend
        self.config_dir = config_dir
        self.policy_digest = hashlib.sha256(policy_bytes).digest()
        self.workspaces = workspaces
        self.trusted = trusted

    def _authorize(self, workspace_id):
        current = _read_policy(self.config_dir)
        if current is None or hashlib.sha256(current).digest() != self.policy_digest:
            raise PermissionError('Owner Git policy changed; audited restart required')
        if workspace_id not in self.workspaces:
            raise PermissionError('Workspace is outside owner Git commit policy')
        for entry in self.backend.registry.list_all():
            root = Path(entry['path']).resolve()
            if any(target == root or target.is_relative_to(root) for target in self.trusted):
                raise PermissionError('Owner Git authority overlaps an exposed workspace')
        workspace = self.backend.registry.get(workspace_id)
        root = Path(workspace.path).resolve(strict=True)
        identity = root.stat()
        if (str(root), identity.st_dev, identity.st_ino) != self.workspaces[workspace_id]:
            raise PermissionError('Owner Git workspace registration identity changed')

    def prepare(self, workspace_id, message, timestamp):
        self._authorize(workspace_id)
        return self.backend.prepare(workspace_id, message, timestamp)

    def commit(self, workspace_id, message, timestamp, receipt):
        self._authorize(workspace_id)
        return self.backend.commit(workspace_id, message, timestamp, receipt)


def load_approved_commits(config_dir, registry, sandbox, manager):
    """Absent policy keeps publication locked; callers cannot supply authority."""
    raw = _read_policy(config_dir)
    if raw is None:
        return None
    data = _decode(raw)
    fields = {'version', 'author_name', 'author_email', 'verification_key', 'ledger_path', 'workspaces'}
    if (not isinstance(data, dict) or set(data) != fields or type(data['version']) is not int or data['version'] != 1):
        raise PermissionError('Invalid owner Git policy schema')
    if not isinstance(data['verification_key'], str) or not re.fullmatch('[0-9a-f]{64}', data['verification_key']):
        raise PermissionError('Owner Git policy requires an exact Ed25519 public key')
    ledger = data['ledger_path']
    if (not isinstance(ledger, str) or not ledger.startswith('/') or ledger.startswith('//')
            or str(PurePosixPath(ledger)) != ledger or '..' in PurePosixPath(ledger).parts):
        raise PermissionError('Owner Git ledger requires a canonical absolute path')
    ids = data['workspaces']
    if (not isinstance(ids, list) or not 1 <= len(ids) <= 128
            or any(not isinstance(value, str) or not value or value == '*' for value in ids)
            or len(set(ids)) != len(ids)):
        raise PermissionError('Owner Git policy requires explicit unique workspace IDs')
    trusted = [Path(config_dir).resolve(), Path(ledger).resolve(),
               Path(manager.state_dir).resolve(), Path(__file__).resolve().parent]
    for entry in registry.list_all():
        root = Path(entry['path']).resolve()
        if any(target == root or target.is_relative_to(root) for target in trusted):
            raise PermissionError('Owner Git authority overlaps an exposed workspace')
    workspaces = {}
    for workspace_id in ids:
        workspace = registry.get(workspace_id)
        if not workspace.writable or not workspace.allow_git:
            raise PermissionError('Owner Git policy conflicts with registered workspace permissions')
        root = Path(workspace.path).resolve(strict=True)
        identity = root.stat()
        workspaces[workspace_id] = (str(root), identity.st_dev, identity.st_ino)
    verifier = GitApprovalVerifier(Ed25519PublicKey.from_public_bytes(bytes.fromhex(data['verification_key'])),
                                   ledger, existing_only=True)
    backend = ApprovedGitCommits(registry, sandbox, verifier,
        author_name=data['author_name'], author_email=data['author_email'], job_manager=manager)
    return _PolicyCommits(backend, config_dir, raw, workspaces, trusted)
