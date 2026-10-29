"""One owner-controlled workspace policy shared by production service roles.

Credentials and signing keys are deliberately not part of this document.
Legacy configurations do not load it implicitly.
"""
from __future__ import annotations

import os
from pathlib import Path
import re
import stat

import yaml

from agentporter.scoped_https import _NoAliasOwnerPolicyLoader


TRUSTED_UID = 0
SHARED_POLICY_PATH = Path('/etc/agentporter/production-workspace-policy.yaml')
MAX_POLICY_BYTES = 128 * 1024
CAPABILITIES = {
    'readable': None, 'writable': 'writable', 'execute': 'allow_execute',
    'git': 'allow_git', 'artifacts': 'allow_artifacts',
    'agent_dispatch': 'allow_agent_dispatch',
}
SPECIALIZED = {
    'allow_scinet_diagnostic': 'scinet_diagnostic',
    'allow_scinet_training': 'scinet_training',
    'allow_venkata_ssh': 'venkata_ssh',
    'allow_venkata_transfer': 'venkata_transfer',
}


def _deny():
    raise PermissionError('Invalid owner-controlled production workspace policy')


def _canonical_root(value):
    if not isinstance(value, str) or not Path(value).is_absolute():
        _deny()
    root = Path(value)
    if str(root.resolve(strict=True)) != value or not root.is_dir():
        _deny()
    return root


def _protected_path(value):
    # Root issues these control paths after canonical validation. Readers must
    # not need traversal into another service's private directories merely to
    # enforce the deny. Check every accessible ancestor for symlinks; an opaque
    # protected suffix remains a deny, never a readable/writable registration.
    if (not isinstance(value, str) or not Path(value).is_absolute()
            or os.path.normpath(value) != value or '\x00' in value):
        _deny()
    path = Path(value)
    for node in reversed((path, *path.parents)):
        try: info = node.lstat()
        except PermissionError: break
        if stat.S_ISLNK(info.st_mode): _deny()
    return path


class WorkspacePolicy:
    def __init__(self, document):
        required = {'version','workspace_defaults','delegation','approval','workspaces','workspace_overrides'}
        if (not isinstance(document, dict) or not required <= set(document)
                or set(document) - required - {'protected_paths'}
                or type(document['version']) is not int or document['version'] != 1):
            _deny()
        defaults = document['workspace_defaults']
        if (not isinstance(defaults, dict) or set(defaults) != set(CAPABILITIES)
                or any(type(v) is not bool for v in defaults.values())):
            _deny()
        delegation = document['delegation']
        if (not isinstance(delegation, dict)
                or set(delegation) != {'enabled_by_default','read_only_default','writable_with_authorization'}
                or any(type(v) is not bool for v in delegation.values())
                or delegation['read_only_default'] is not True):
            _deny()
        if document['approval'] != {'commit':'required','push':'required','destructive_operations':'required'}:
            _deny()
        registrations = document['workspaces']
        overrides = document['workspace_overrides']
        if (not isinstance(registrations, dict) or not registrations or len(registrations) > 512
                or not isinstance(overrides, dict) or not set(overrides) <= set(registrations)):
            _deny()
        for name, row in registrations.items():
            if (not isinstance(name, str) or not re.fullmatch(r'[A-Za-z0-9_-]{1,64}', name)
                    or not isinstance(row, dict)
                    or set(row) - {'path','description','local_http_ports', *SPECIALIZED}
                    or 'path' not in row):
                _deny()
            _canonical_root(row['path'])
            if 'description' in row and not isinstance(row['description'], str):
                _deny()
            if any(type(row.get(k,False)) is not bool for k in SPECIALIZED):
                _deny()
            ports = row.get('local_http_ports', [])
            if not isinstance(ports,list) or any(type(p) is not int or not 1 <= p <= 65535 for p in ports):
                _deny()
        for name, override in overrides.items():
            if (not isinstance(override,dict) or set(override) != {'reason','capabilities'}
                    or not isinstance(override['reason'],str) or not override['reason'].strip()
                    or len(override['reason']) > 2048
                    or not isinstance(override['capabilities'],dict)
                    or not set(override['capabilities']) <= set(CAPABILITIES)
                    or any(type(v) is not bool for v in override['capabilities'].values())):
                _deny()
        protected = document.get('protected_paths', [])
        if not isinstance(protected,list):
            _deny()
        self.protected_paths = tuple(_protected_path(p) for p in protected)
        self.defaults = dict(defaults)
        self.delegation = dict(delegation)
        self.registrations = {k:dict(v) for k,v in registrations.items()}
        self.overrides = {k:{'reason':v['reason'], 'capabilities':dict(v['capabilities'])} for k,v in overrides.items()}
        self.workspaces = {name:self.definition(name, row) for name,row in registrations.items()}

    def capabilities(self, name):
        result = dict(self.defaults)
        result.update(self.overrides.get(name,{}).get('capabilities',{}))
        result['agent_dispatch'] &= self.delegation['enabled_by_default']
        return result

    def definition(self, name, registration):
        result = dict(registration)
        result.update({field:value for cap,value in self.capabilities(name).items()
                       if (field := CAPABILITIES[cap]) is not None})
        result['auto_discover'] = False
        return result

    def exceptions(self):
        return {k:{'reason':v['reason'], 'capabilities':dict(v['capabilities'])} for k,v in self.overrides.items()}

    def public_scopes(self, registry):
        scopes = {}
        for row in registry.list_all():
            name = row['workspace_id']; caps = self.capabilities(name)
            ws = registry.get(name)
            ops = set()
            if caps['readable']: ops.add('read')
            if ws.allow_git: ops.update(('git_read','git_fetch'))
            if ws.writable: ops.add('write')
            # General file edits do not grant raw Git-metadata writes. Existing
            # git_add/checkout backends can invoke repository helpers with that
            # metadata writable; publication remains locked until a separately
            # authorized, fixed-purpose publisher is available.
            if ws.allow_execute: ops.add('exec')
            if ws.allow_agent_dispatch: ops.add('dispatch')
            if ws.allow_agent_dispatch and ws.writable and self.delegation['writable_with_authorization']:
                ops.add('dispatch_write')
            # Specialized grants are explicit registrations, never inherited defaults.
            for field, operation in SPECIALIZED.items():
                if self.registrations.get(name,{}).get(field,False):
                    ops.add(operation)
            scopes[name] = ops
        return scopes

    def check_path(self, workspace_id, path, operation):
        if workspace_id not in self.workspaces:
            _deny()
        root = Path(self.workspaces[workspace_id]['path'])
        target = Path(path).resolve(strict=False)
        if target != root and not target.is_relative_to(root):
            _deny()
        if any(target == p or target.is_relative_to(p) for p in self.protected_paths):
            _deny()
        required = {'write':'writable','exec':'execute','dispatch':'agent_dispatch','read':'readable'}[operation]
        if not self.capabilities(workspace_id)[required]:
            _deny()
        # An explicit child exception cannot be bypassed through a parent registration.
        for name, row in self.workspaces.items():
            child = Path(row['path'])
            if ((target == child or target.is_relative_to(child))
                    and not self.capabilities(name)[required]):
                _deny()


def load_workspace_policy(path=SHARED_POLICY_PATH):
    path = Path(path)
    try:
        # A root-controlled shared document may be readable by both roles, never writable by them.
        for parent in path.parents:
            info = parent.lstat()
            if (not stat.S_ISDIR(info.st_mode) or info.st_uid not in {0,TRUSTED_UID}
                    or info.st_mode & 0o022 and not info.st_mode & stat.S_ISVTX):
                _deny()
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != TRUSTED_UID
                    or info.st_nlink != 1 or info.st_mode & 0o022 or info.st_size > MAX_POLICY_BYTES):
                _deny()
            raw = os.read(fd,MAX_POLICY_BYTES + 1)
            if len(raw) > MAX_POLICY_BYTES: _deny()
        finally:
            os.close(fd)
        return WorkspacePolicy(yaml.load(raw, Loader=_NoAliasOwnerPolicyLoader))
    except (OSError, ValueError, TypeError, KeyError, yaml.YAMLError, RecursionError):
        _deny()


def shared_policy_reference(document):
    """Return a policy only for an explicit new-role reference; legacy YAML is untouched."""
    if not isinstance(document,dict) or document.get('version') != 2:
        return None
    if (set(document) != {'version','policy_file'} or type(document['version']) is not int
            or document['policy_file'] != str(SHARED_POLICY_PATH)):
        _deny()
    return load_workspace_policy(SHARED_POLICY_PATH)
