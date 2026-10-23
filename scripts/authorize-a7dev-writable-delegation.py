#!/usr/bin/python3
"""Plan/apply explicit A7Dev writable dispatch grants for existing project roots.

Run as agentporter-dev. This never adds registry/runtime roots or expands network,
never changes production, and never reads credentials. Install the reviewed source
snapshot first. Apply/rollback retain the existing stopped/quiet service gates.
"""
import argparse
import contextlib
import fcntl
import copy
import importlib.util
import json
import os
from pathlib import Path
import pwd
import re
import stat
import subprocess

import yaml

_source = Path(__file__).with_name('authorize-a7dev-project-delegation.py')
_spec = importlib.util.spec_from_file_location('a7dev_delegation_storage', _source)
storage = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(storage)
# The immutable installed v1 helper retains ownership of its existing record.
# New grants select a unique namespace only after computing the exact plan hash.


def documents(inputs):
    try:
        return [yaml.load(inputs[name], Loader=storage.UniqueLoader) for name in storage.FILES]
    except yaml.YAMLError:
        raise RuntimeError('Invalid private delegation configuration YAML') from None


def transform(inputs, release, workspaces):
    require = storage.require
    policy, registry, runtime = documents(inputs)
    require(isinstance(policy, dict) and policy.get('version') == 1
            and isinstance(policy.get('workspaces'), dict), 'Invalid public policy')
    require(isinstance(registry, dict) and isinstance(registry.get('workspaces'), dict), 'Invalid registry')
    require(isinstance(runtime, dict) and runtime.get('enabled') is True
            and runtime.get('profile') == 'development', 'Not an enabled development runtime')
    roots = runtime.get('allowed_workspace_roots')
    require(isinstance(roots, list) and all(isinstance(r, dict) and set(r) == {'path', 'writable'}
            and isinstance(r['path'], str) and type(r['writable']) is bool for r in roots), 'Invalid runtime roots')
    require(len({r['path'] for r in roots}) == len(roots), 'Duplicate runtime roots')
    require(workspaces and len(set(workspaces)) == len(workspaces), 'Name each workspace exactly once')
    updated = copy.deepcopy(policy)
    updated_runtime = copy.deepcopy(runtime)
    for name in workspaces:
        require(name in storage.EXPECTED_ROOTS and name not in storage.PROTECTED, 'Protected/unknown workspace: ' + name)
        row = registry['workspaces'].get(name, {})
        scope = updated['workspaces'].get(name, {})
        path = storage.EXPECTED_ROOTS[name]
        require(row.get('path') == scope.get('path') == path
                and os.path.realpath(path) == path and Path(path).is_dir(), 'Workspace root mismatch: ' + name)
        require(all(row.get(k) is True for k in ('writable', 'allow_execute', 'allow_agent_dispatch')),
                'Registry does not permit writable delegation: ' + name)
        require(isinstance(scope.get('operations'), list)
                and {'write', 'dispatch'} <= set(scope['operations']), 'Existing write/dispatch grant required: ' + name)
        require(any(r['path'] == path for r in roots), 'Runtime has no admitted root: ' + name)
        # Match DevelopmentRuntime._workspace: a selected parent containing
        # another admitted root cannot be writable. An independently mounted
        # leaf stays confined even when a read-only ancestor is registered.
        require(not any(r['path'] != path and Path(r['path']).is_relative_to(path) for r in roots),
                'Overlapping writable workspace parent: ' + name)
        next(r for r in updated_runtime['allowed_workspace_roots'] if r['path'] == path)['writable'] = True
        if 'dispatch_write' not in scope['operations']:
            scope['operations'].append('dispatch_write')
    output = {n: inputs[n] for n in storage.FILES}
    output[storage.FILES[0]] = yaml.safe_dump(updated, sort_keys=False).encode()
    if updated_runtime != runtime:
        output[storage.FILES[2]] = yaml.safe_dump(updated_runtime, sort_keys=False).encode()
    plan = {'version': 1, 'release': str(release), 'writable_workspaces': sorted(workspaces),
            'production_changed': False, 'network_changed': False,
            'before': {n: storage.digest(inputs[n]) for n in storage.FILES + (storage.HTTPS,)},
            'after': {n: storage.digest(output[n]) for n in storage.FILES}}
    return output, plan




def select_eligible(inputs, release, probe=None):
    """Select exact existing owner-authorized project roots; report every denial."""
    policy, registry, runtime = documents(inputs)
    storage.require(isinstance(registry, dict) and isinstance(registry.get('workspaces'), dict), 'Invalid registry')
    storage.require(isinstance(policy, dict) and isinstance(policy.get('workspaces'), dict), 'Invalid public policy')
    selected, excluded, blocked = [], [], []
    for name, row in sorted(registry['workspaces'].items()):
        scope = policy['workspaces'].get(name, {})
        if name in storage.PROTECTED:
            excluded.append({'workspace': name, 'reason': 'protected_project'})
        elif not isinstance(row, dict) or row.get('writable') is not True:
            excluded.append({'workspace': name, 'reason': 'registry_read_only'})
        elif row.get('allow_execute') is not True or row.get('allow_agent_dispatch') is not True:
            excluded.append({'workspace': name, 'reason': 'registry_delegation_not_admitted'})
        elif not isinstance(scope, dict) or not isinstance(scope.get('operations'), list) or not {'write', 'dispatch'} <= set(scope['operations']):
            excluded.append({'workspace': name, 'reason': 'public_write_and_dispatch_not_admitted'})
        else:
            try:
                transform(inputs, release, [name])
                if probe is not None:
                    probe(release, row['path'])
            except (RuntimeError, ValueError, OSError) as error:
                # Transform diagnostics include IDs/reasons, never credentials.
                blocked.append({'workspace': name, 'reason': str(error)})
            else:
                selected.append(name)
    return selected, {'selected_count': len(selected), 'excluded_count': len(excluded),
                      'blocked_count': len(blocked), 'excluded': excluded, 'blocked': blocked}



def probe_writable_workspace(release, path):
    """Apply the actual immutable launcher's metadata guards before granting."""
    code = ('import sys; from pathlib import Path; '
            'from agentporter.agents.development import DevelopmentRuntime; '
            'runtime=object.__new__(DevelopmentRuntime); '
            'runtime._masks(Path(sys.argv[1]), True)')
    try:
        result = subprocess.run([str(release / 'venv/bin/python'), '-I', '-B', '-c', code, path],
                                capture_output=True, text=True, timeout=20, check=False)
    except (OSError, subprocess.TimeoutExpired):
        raise RuntimeError('Writable confinement metadata preflight unavailable or timed out') from None
    if result.returncode:
        # Worker diagnostics can contain file names; keep owner plans private.
        raise RuntimeError('Writable confinement metadata/hardlink/protected-layout preflight failed')


def recovery_name(plan_sha256):
    storage.require(isinstance(plan_sha256, str) and re.fullmatch('[0-9a-f]{64}', plan_sha256),
                    'Invalid recovery plan SHA')
    return 'writable-delegation-recovery-' + plan_sha256


@contextlib.contextmanager
def mutation_lock(config_fd, uid):
    fd = os.open('writable-delegation.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK,
                 0o600, dir_fd=config_fd)
    try:
        info = os.fstat(fd)
        storage.require(stat.S_ISREG(info.st_mode) and info.st_uid == uid
                        and info.st_nlink == 1 and stat.S_IMODE(info.st_mode) == 0o600,
                        'Unsafe writable delegation lock')
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise RuntimeError('Another writable delegation mutation is active') from None
        yield
    finally:
        os.close(fd)


def apply_plan(config_fd, uid, inputs, output, plan, expected):
    storage.require(storage.digest(storage.canonical(plan)) == expected, 'Review plan SHA mismatch')
    with mutation_lock(config_fd, uid):
        storage.RECOVERY = recovery_name(expected)
        storage.apply(config_fd, uid, inputs, output, plan, expected)


def rollback_plan(config_fd, uid, expected):
    namespace = recovery_name(expected)
    with mutation_lock(config_fd, uid):
        storage.RECOVERY = namespace
        recovery_fd = storage.open_directory(storage.CONFIG / storage.RECOVERY, uid)
        try:
            storage.rollback(config_fd, recovery_fd, uid, expected)
        finally:
            os.close(recovery_fd)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument('--plan', action='store_true')
    mode.add_argument('--apply', action='store_true')
    mode.add_argument('--rollback', action='store_true')
    targets = parser.add_mutually_exclusive_group()
    targets.add_argument('--workspace', action='append', default=[])
    targets.add_argument('--all-eligible', action='store_true')
    parser.add_argument('--expected-plan-sha256')
    args = parser.parse_args()
    uid = pwd.getpwnam('agentporter-dev').pw_uid
    storage.require(os.geteuid() == uid and uid != 0, 'Run only as agentporter-dev, never root')
    fd = storage.open_directory(storage.CONFIG, uid)
    try:
        if args.apply or args.rollback:
            storage.require(args.expected_plan_sha256 and re.fullmatch('[0-9a-f]{64}', args.expected_plan_sha256), 'Supply reviewed plan SHA')
            storage.quiet_and_stopped()
        if args.rollback:
            rollback_plan(fd, uid, args.expected_plan_sha256)
            print(json.dumps({'rolled_back': True, 'recovery': str(storage.CONFIG / recovery_name(args.expected_plan_sha256))}))
            return
        release = storage.CURRENT.resolve(strict=True)
        storage.require(release.parent == Path('/opt/agentporter-development/versions')
                        and re.fullmatch(r'\d{8}T\d{6}\.\d{6}Z', release.name), 'Unexpected development release')
        source = release / 'src/agentporter/client_policy.py'
        storage.require('dispatch_write' in source.read_text(), 'Install reviewed writable-delegation source first')
        inputs = {n: storage.private_read(fd, n, uid) for n in storage.FILES + (storage.HTTPS,)}
        workspaces = args.workspace
        eligibility = None
        if args.all_eligible:
            workspaces, eligibility = select_eligible(inputs, release, probe_writable_workspace)
            storage.require(workspaces, 'No admitted writable project leaves are eligible')
        output, plan = transform(inputs, release, workspaces)
        if not args.all_eligible:
            registry = documents(inputs)[1]['workspaces']
            for name in workspaces:
                probe_writable_workspace(release, registry[name]['path'])
        if eligibility is not None:
            plan['eligibility'] = eligibility
        if args.apply:
            apply_plan(fd, uid, inputs, output, plan, args.expected_plan_sha256)
        plan_sha = storage.digest(storage.canonical(plan))
        print(json.dumps({'applied': args.apply, 'plan_sha256': plan_sha, 'plan': plan,
                          'recovery': str(storage.CONFIG / recovery_name(plan_sha))}, sort_keys=True))
    finally:
        os.close(fd)


if __name__ == '__main__':
    main()
