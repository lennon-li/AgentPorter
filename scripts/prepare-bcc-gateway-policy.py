#!/usr/bin/env python3
"""Pure BCC gateway policy planning; never reads or applies live configuration."""
from __future__ import annotations

import copy
from pathlib import PurePosixPath

from agentporter.client_policy import SCOPES

BUDGET = {'memory_bytes': 2 * 1024**3, 'pids': 128,
          'cpu_quota_us': 200000, 'cpu_period_us': 100000}
PROTECTED = ('/home/yeli/.config/agentporter', '/home/yeli/.local/state/agentporter',
             '/home/yeli/.cache/agentporter', '/opt/agentporter-bcc', '/usr/local/libexec')
REPOS = PurePosixPath('/home/yeli/repos')


def canonical(value):
    if (not isinstance(value, str) or not value.startswith('/') or value.startswith('//')
            or str(PurePosixPath(value)) != value or '..' in PurePosixPath(value).parts):
        raise ValueError('Canonical absolute workspace path required')
    return PurePosixPath(value)


def prepare(documents, *, grants):
    """Return a new config set with only explicitly selected public grants.

    Workspace registrations and existing ingress/auth settings are preserved.
    This does not provision cgroups, enable relays, create credentials, approve
    Git publication, or verify live filesystem identities. Those remain separate
    owner-controlled deployment checks.
    """
    if not isinstance(documents, dict) or not isinstance(grants, dict) or not grants:
        raise ValueError('Explicit gateway documents and nonempty public grants required')
    if any(name in documents for name in ('development-runtime.yaml', 'public-client-policy.yaml',
                                         'gateway-job-resources.yaml')):
        raise PermissionError('Existing hardened or worker profile requires explicit reconciliation')
    planned = copy.deepcopy(documents)
    config = planned.get('config.yaml')
    registry = planned.get('workspaces.yaml', {}).get('workspaces')
    if not isinstance(config, dict) or not isinstance(registry, dict):
        raise ValueError('Gateway config and workspace registry required')
    if config.get('security', {}).get('auth', 'api_key') != 'api_key':
        raise PermissionError('Gateway must preserve API-key authentication')
    scopes = {}
    for name, operations in grants.items():
        if not isinstance(name, str) or not name or name == '*' or name not in registry:
            raise ValueError('Every grant must select one registered workspace')
        row = registry[name]
        if not isinstance(row, dict):
            raise ValueError('Invalid registered workspace')
        path = canonical(row.get('path'))
        if path == REPOS or not path.is_relative_to(REPOS):
            raise PermissionError('Select individual BCC projects, not the repository parent')
        if any(canonical(protected).is_relative_to(path) for protected in PROTECTED):
            raise PermissionError('Public workspace overlaps protected gateway data')
        if (not isinstance(operations, list) or not operations
                or any(not isinstance(op, str) or op not in SCOPES for op in operations)
                or len(operations) != len(set(operations))):
            raise ValueError('Explicit distinct supported operation scopes required')
        selected = set(operations)
        if selected & {'write', 'git_write', 'git_commit', 'git_push', 'dispatch_write'} and row.get('writable', True) is not True:
            raise PermissionError('Write grant conflicts with read-only registration')
        if 'exec' in selected and row.get('allow_execute', True) is not True:
            raise PermissionError('Execution grant conflicts with registration')
        if any(op.startswith('git_') for op in selected) and row.get('allow_git', True) is not True:
            raise PermissionError('Git grant conflicts with registration')
        if selected & {'dispatch', 'dispatch_write'} and row.get('allow_agent_dispatch', False) is not True:
            raise PermissionError('Dispatch grant conflicts with registration')
        if 'dispatch_write' in selected and not {'write', 'dispatch'} <= selected:
            raise PermissionError('Writable dispatch needs explicit write and dispatch scopes')
        scopes[name] = {'path': str(path), 'operations': list(operations)}
    config.setdefault('sandbox', {}).update(workspace_transactions=True, network=False)
    planned['public-client-policy.yaml'] = {'version': 1, 'workspaces': scopes}
    planned['gateway-job-resources.yaml'] = {'version': 1, 'job_resources': dict(BUDGET)}
    return planned
