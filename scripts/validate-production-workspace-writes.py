#!/usr/bin/env python3
"""Fixed namespace/ACL check under the actual production worker UID; no model call."""
import argparse
import ctypes
import json
import os
from pathlib import Path
import subprocess
import uuid

from agentporter.agents.development import DevelopmentRuntime
from agentporter.workspace_policy import load_workspace_policy
from agentporter.workspace_views import CowWorkspaceTransaction
from agentporter.workspace_transactions import WorkspaceTransactionError
from agentporter.workspaces.registry import WorkspaceRegistry


def namespace_code(fixture):
    return f"""from pathlib import Path
import os
for name in os.listdir('/proc/self/fd'):
    if int(name) <= 2: continue
    try: os.fstat(int(name))
    except OSError: continue
    raise AssertionError('host descriptor leaked')
assert 'NoNewPrivs:\\t1' in Path('/proc/self/status').read_text()
folder = Path({fixture!r})
assert (folder/'existing.txt').read_text() == 'before'
assert not Path('/etc/agentporter/approval-issuer.key').exists()
assert not Path('/var/lib/agentporter-worker/config').exists()
(folder/'existing.txt').write_text('after')
(folder/'new.txt').write_text('new')
print('WORKSPACE_WRITE_NAMESPACE_OK')
"""


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--workspace', required=True)
    parser.add_argument('--fixture', required=True)
    args = parser.parse_args()
    if os.getuid() == 0 or not args.fixture.startswith('.a7-permission-check-') or '/' in args.fixture:
        raise PermissionError('Invalid validation identity or fixture')
    if ctypes.CDLL(None).prctl(38, 1, 0, 0, 0):
        raise PermissionError('NoNewPrivileges could not be enforced')
    policy = load_workspace_policy()
    source = Path(policy.workspaces[args.workspace]['path'])
    registry = WorkspaceRegistry(policy.workspaces, workspace_policy=policy)
    state = Path('/var/lib/agentporter-worker/state')
    runtime = DevelopmentRuntime(Path('/var/lib/agentporter-worker/config'), state, registry)
    protected = [p.relative_to(source).as_posix() for p in policy.protected_paths if p.is_relative_to(source) and p != source]
    protected.extend(rel.as_posix() for rel, _, _, _ in runtime._masks(source, True, private_writes=True)
                     if '.git' not in rel.parts)
    tx = CowWorkspaceTransaction(source, state / 'permission-validation', uuid.uuid4().hex,
                                 protected_paths=protected)
    view = tx.prepare()
    launch = None
    try:
        code = namespace_code(args.fixture)
        launch = runtime._build('fixture', {}, {'executable': str(Path('/usr/bin/python3').resolve()), 'credentials': {}},
                                view, True, ['/usr/bin/python3', '-c', code], source_workspace=source,
                                workspace_descriptor=tx.view_descriptor)
        result = subprocess.run(launch.command, pass_fds=launch.pass_fds, capture_output=True,
                                text=True, timeout=10)
        if result.returncode or 'WORKSPACE_WRITE_NAMESPACE_OK' not in result.stdout:
            raise PermissionError('Worker namespace check failed: ' + json.dumps({
                'exit_code': result.returncode, 'stdout': result.stdout[-8192:],
                'stderr': result.stderr[-8192:]}))
        if (source / args.fixture / 'existing.txt').read_text() != 'before':
            raise PermissionError('Original workspace changed before publication')
        summary = tx.apply()
        assert (source / args.fixture / 'existing.txt').read_text() == 'after'
    finally:
        if launch is not None: launch.cleanup()
        tx.cleanup()
    denial = CowWorkspaceTransaction(source, state / 'permission-validation', uuid.uuid4().hex)
    try:
        view = denial.prepare()
        (view / args.fixture / 'existing.txt').unlink()
        try: denial.apply()
        except WorkspaceTransactionError: pass
        else: raise PermissionError('Unapproved deletion was accepted')
        assert (source / args.fixture / 'existing.txt').read_text() == 'after'
    finally: denial.cleanup()
    print(json.dumps({'worker_uid': os.getuid(), 'no_new_privileges': True,
                      'namespace_write': True, 'publication': summary,
                      'unapproved_delete_rejected': True}, sort_keys=True))


if __name__ == '__main__': main()
