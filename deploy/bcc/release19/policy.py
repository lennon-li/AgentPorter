"""Pure production policy transform for the owner's writable BCC projects.

No credentials, files, processes, mounts, or services are touched here.
"""
from copy import deepcopy
from pathlib import PurePosixPath

AGENTS = ['jax', 'liz', 'prof', 'phil', 'wei', 'ming', 'argie']
OPERATIONS = ['read', 'write', 'exec', 'git_read', 'git_write', 'dispatch', 'dispatch_write']


def prepare(gateway, worker):
    gateway, worker = deepcopy(gateway), deepcopy(worker)
    rows = gateway['workspaces.yaml']['workspaces']
    selected = {}
    for name, row in rows.items():
        path = PurePosixPath(row['path'])
        if path == PurePosixPath('/home/yeli/repos'):
            continue
        if (not name or not path.is_absolute() or '..' in path.parts
                or len(path.parts) != 5 or path.parts[:4] != ('/', 'home', 'yeli', 'repos')):
            raise PermissionError('Production selects individual canonical BCC projects only')
        if row.get('writable', True) is not True:
            continue
        selected[name] = deepcopy(row)
        selected[name].update(path=str(path), writable=True,
                              allow_execute=True, allow_git=True, allow_agent_dispatch=True)
    if not selected:
        raise PermissionError('No writable projects selected')
    if len({row['path'] for row in selected.values()}) != len(selected):
        raise PermissionError('Duplicate project aliases require reconciliation')
    runtime = worker['development-runtime.yaml']
    if (runtime.get('profile') != 'development' or runtime.get('enabled') is not True
            or runtime.get('network_enabled') is not True or runtime.get('egress_policy') != 'provider_origin'
            or runtime.get('public_client_policy_required') is not True):
        raise PermissionError('Expected isolated provider-origin worker')
    allowed = {row['path']: row['writable'] for row in runtime['allowed_workspace_roots']}
    for name, row in selected.items():
        old = worker['workspaces.yaml']['workspaces'].get(name)
        if old and old['path'] != row['path']:
            raise PermissionError('Worker workspace ID has a different path')
        if any(path != row['path'] and
               (PurePosixPath(path).is_relative_to(row['path']) or PurePosixPath(row['path']).is_relative_to(path))
               for path in allowed):
            raise PermissionError('Overlapping worker roots require reconciliation')
        gateway['workspaces.yaml']['workspaces'][name] = deepcopy(row)
        worker['workspaces.yaml']['workspaces'][name] = {
            key: row[key] for key in ('path','writable','allow_execute','allow_git','allow_agent_dispatch')}
        allowed[row['path']] = True
        worker['public-client-policy.yaml']['workspaces'][name] = {
            'path': row['path'], 'operations': list(OPERATIONS)}
    runtime['allowed_workspace_roots'] = [{'path': path, 'writable': writable}
                                          for path, writable in allowed.items()]
    runtime['production_relay_agents'] = list(AGENTS)
    gateway['public-client-policy.yaml'] = {'version': 1, 'workspaces': {
        name: {'path': row['path'], 'operations': list(OPERATIONS)} for name, row in selected.items()}}
    for docs in (gateway, worker):
        docs['config.yaml'].setdefault('sandbox', {}).update(workspace_transactions=True, network=False)
        modes = docs.setdefault('action-policy.yaml', {'version': 1, 'action_modes': {}})['action_modes']
        modes.update(git_commit='SCOPE', git_push='LOCKED')
        for row in docs['public-client-policy.yaml']['workspaces'].values():
            row['operations'] = [op for op in row['operations'] if op != 'git_push']
    gateway['gateway-job-resources.yaml'] = {'version': 1, 'job_resources': {
        'memory_bytes': 2147483648, 'pids': 128, 'cpu_quota_us': 200000, 'cpu_period_us': 100000}}
    paths = {name: row['path'] for name, row in selected.items()}
    scope = {'version': 1, 'workspaces': paths}
    worker['delegation-relay-scope.yaml'] = deepcopy(scope)
    worker['delegation-relay-write-scope.yaml'] = deepcopy(scope)
    gateway['delegation-relay-write-scope.yaml'] = deepcopy(scope)
    gateway['delegation-upstream.yaml'] = {'version': 1, 'host': '127.0.0.1', 'port': 8876,
                                           'workspaces': list(paths)}
    return gateway, worker
