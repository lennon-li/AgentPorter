#!/usr/bin/python3
"""Owner-approved A7Dev project delegation; run only as agentporter-dev.

Plan is read-only. Apply requires the reviewed plan SHA, a stopped service,
zero admissions/jobs, and byte-matching inputs. No credential contents are read.
Rollback accepts only exact prepared/applied bytes and preserves newer changes.
"""
import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import secrets
import sqlite3
import stat
import subprocess

import yaml

CONFIG = Path('/var/lib/agentporter-dev/config')
STATE = Path('/var/lib/agentporter-dev/state')
CURRENT = Path('/opt/agentporter-development/current')
FILES = ('public-client-policy.yaml', 'workspaces.yaml', 'development-runtime.yaml')
HTTPS = 'public-https.yaml'
RECOVERY = 'project-delegation-recovery-v1'
POLICY_SHA = '97fbbeb9abfb896f4022647218dbc77f80fbfa2bbb3bfea25101756dd4b92043'
RUNTIME_SHA = '308537f5a2da0bf19705fbd5219ffceccd2af517b1a08ebc7318968d3205b863'
PROTECTED = {'obsidian', 'agentporter', 'AgentPorter', 'asgard-hermes-review', 'repos'}
EXPECTED_ROOTS = {'m3-poc': '/home/operator/m3-agent-poc', 'insider': '/home/operator/repos/insider', 'PAGe': '/home/operator/repos/PAGe', 'm3': '/home/operator/repos/m3', 'obsidian': '/home/operator/repos/obsidian', 'shiny': '/home/operator/repos/shiny', 'cranary': '/home/operator/repos/cranary', 'agentporter-dev': '/home/operator/agent-work/agentporter-dev', 'agentporter': '/home/operator/repos/AgentPorter', 'repos': '/home/operator/repos', 'asgard-hermes-review': '/home/operator/repos/AgentPorter/runtime/asgard-hermes-exposure', 'opcc': '/home/operator/repos/opcc', 'RangeAhead': '/home/operator/repos/RangeAhead', 'HMA': '/home/operator/repos/HMA', 'dataganger': '/home/operator/repos/dataganger', 'epiweave': '/home/operator/repos/epiweave', 'ALL': '/home/operator/repos/ALL', 'careDX': '/home/operator/repos/careDX', 'cranary-jax-wt': '/home/operator/repos/cranary-jax-wt', 'scinet-home': '/home/operator/repos/scinet-home', 'clientAgent': '/home/operator/repos/clientAgent', 'courieR': '/home/operator/repos/courieR', 'hermes-jev-acceptance-20261018': '/home/operator/repos/hermes-jev-acceptance-20261018', 'node-which': '/home/operator/repos/node-which', 'IRVRI': '/home/operator/repos/IRVRI', 'dogfooding': '/home/operator/repos/dogfooding', 'ONgeoR': '/home/operator/repos/ONgeoR', 'covid-positivity-forecasting': '/home/operator/repos/covid-positivity-forecasting', 'gambling': '/home/operator/repos/gambling', 'which': '/home/operator/repos/which', 'legionella': '/home/operator/repos/legionella', 'IPD': '/home/operator/repos/IPD', 'hermes-jev-bcc-package-20261018': '/home/operator/repos/hermes-jev-bcc-package-20261018', 'Qman': '/home/operator/repos/Qman', 'biostats.ai': '/home/operator/repos/biostats.ai', 'preview-jqtrwy87': '/home/operator/repos/preview-jqtrwy87', 'ONgeoRapp': '/home/operator/repos/ONgeoRapp', 'AgentPorter': '/home/operator/repos/AgentPorter', 'agent-web-search': '/home/operator/repos/agent-web-search', 'IRVRI.Rcheck': '/home/operator/repos/shiny/IRVRI.Rcheck', 'compliance': '/home/operator/repos/shiny/compliance', 'EasyMaps': '/home/operator/repos/shiny/EasyMaps', 'EasyMap2.1': '/home/operator/repos/shiny/EasyMap2.1', 'CTLOD.Rcheck': '/home/operator/repos/shiny/CTLOD.Rcheck', 'CTLOD': '/home/operator/repos/shiny/CTLOD', 'CUSUM': '/home/operator/repos/shiny/CUSUM'}


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def digest(body):
    return hashlib.sha256(body).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()


class UniqueLoader(yaml.SafeLoader):
    pass


def unique_mapping(loader, node, deep=False):
    result = {}
    for keynode, valnode in node.value:
        key = loader.construct_object(keynode, deep=deep)
        require(isinstance(key, str) and key not in result, 'Duplicate/nonstring YAML key')
        result[key] = loader.construct_object(valnode, deep=deep)
    return result


UniqueLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, unique_mapping)


def normalize_release(value, release):
    if isinstance(value, str):
        return value.replace(str(release) + '/', '__RELEASE__/')
    if isinstance(value, list):
        return [normalize_release(x, release) for x in value]
    if isinstance(value, dict):
        return {k: normalize_release(v, release) for k, v in value.items()}
    return value


def transform(inputs, release):
    require(digest(inputs[FILES[0]]) == POLICY_SHA, 'Public policy differs from reviewed baseline')
    policy, registry, runtime = [yaml.load(inputs[n], Loader=UniqueLoader) for n in FILES]
    require(isinstance(registry, dict) and isinstance(registry.get('workspaces'), dict), 'Malformed registry')
    rows = registry['workspaces']
    require(set(rows) == set(EXPECTED_ROOTS), 'Registry workspace IDs changed')
    for name, expected in EXPECTED_ROOTS.items():
        row = rows[name]
        require(isinstance(row, dict) and row.get('path') == expected, 'Registry root changed: ' + name)
        require(str(Path(expected)) == expected and Path(expected).is_absolute(), 'Noncanonical root')
        require(os.path.realpath(expected) == expected, 'Symlink root: ' + name)
        require(Path(expected).is_dir(), 'Missing/inaccessible workspace directory: ' + name)
        require(all(type(row[k]) is bool for k in ('allow_execute', 'allow_agent_dispatch', 'writable', 'allow_git') if k in row), 'Malformed registry permission')
    require(isinstance(policy, dict) and policy.get('version') == 1 and set(policy.get('workspaces', {})) == set(rows), 'Malformed policy')
    require(isinstance(runtime, dict) and digest(canonical(normalize_release(runtime, release))) == RUNTIME_SHA,
            'Runtime differs from frozen v19 except approved release relocation')
    result_policy, result_registry, result_runtime = copy.deepcopy((policy, registry, runtime))
    admitted = sorted(set(rows) - PROTECTED)
    for name in rows:
        entry = policy['workspaces'][name]
        require(entry['path'] == EXPECTED_ROOTS[name] and isinstance(entry['operations'], list), 'Policy path mismatch')
        if name in PROTECTED:
            require(set(entry['operations']) <= {'read', 'git_read'}, 'Protected public operation')
        else:
            operations = result_policy['workspaces'][name]['operations']
            for operation in ('exec', 'dispatch'):
                if operation not in operations:
                    operations.append(operation)
            result_registry['workspaces'][name]['allow_agent_dispatch'] = True
            result_registry['workspaces'][name]['allow_execute'] = True
    require([n for n, r in result_policy['workspaces'].items() if 'https' in r['operations']] == ['cranary'], 'HTTPS scope changed')
    allowed = result_runtime['allowed_workspace_roots']
    require(all(isinstance(r, dict) and set(r) == {'path', 'writable'} and type(r['writable']) is bool for r in allowed), 'Malformed runtime roots')
    require(len({r['path'] for r in allowed}) == len(allowed), 'Duplicate runtime roots')
    for row in allowed:
        if row['path'] == EXPECTED_ROOTS['shiny']:
            row['writable'] = False
    existing = {r['path'] for r in allowed}
    for name in admitted:
        if EXPECTED_ROOTS[name] not in existing:
            allowed.append({'path': EXPECTED_ROOTS[name], 'writable': False})
            existing.add(EXPECTED_ROOTS[name])
    output = {name: yaml.safe_dump(data, sort_keys=False).encode() for name, data in zip(FILES, (result_policy, result_registry, result_runtime))}
    plan = {'version': 1, 'release': str(release), 'admitted_workspaces': admitted,
            'protected_workspaces': sorted(PROTECTED), 'https_workspaces': ['cranary'],
            'generic_shell_network': False, 'production_changed': False,
            'before': {n: digest(inputs[n]) for n in FILES + (HTTPS,)},
            'after': {n: digest(output[n]) for n in FILES}}
    return output, plan


def open_directory(path, uid):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    s = os.fstat(fd)
    require(s.st_uid == uid and stat.S_IMODE(s.st_mode) == 0o700, 'Unsafe private directory')
    return fd


def private_read(fd, name, uid):
    f = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
    try:
        s = os.fstat(f)
        require(stat.S_ISREG(s.st_mode) and s.st_uid == uid and stat.S_IMODE(s.st_mode) == 0o600 and s.st_nlink == 1 and s.st_size <= 1024 ** 2, 'Unsafe private file: ' + name)
        with os.fdopen(f, 'rb', closefd=False) as stream:
            body = stream.read(1024 ** 2 + 1)
        require(len(body) <= 1024 ** 2, 'Oversized private file')
        return body
    finally:
        os.close(f)


def write(fd, name, body, exclusive=False):
    temp = name if exclusive else '.project-delegation-' + secrets.token_hex(12)
    f = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=fd)
    try:
        with os.fdopen(f, 'wb', closefd=False) as stream:
            stream.write(body)
            stream.flush()
            os.fsync(f)
        if not exclusive:
            os.replace(temp, name, src_dir_fd=fd, dst_dir_fd=fd)
        os.fsync(fd)
    finally:
        os.close(f)
        if not exclusive:
            try:
                os.unlink(temp, dir_fd=fd)
            except FileNotFoundError:
                pass


def quiet_and_stopped():
    process = subprocess.run(['/usr/bin/systemctl', 'is-active', 'agentporter-development.service'], capture_output=True, text=True, timeout=10, check=False)
    require(process.returncode == 3 and process.stdout.strip() in ('inactive', 'failed'), 'Stop A7Dev before applying/rollback')
    require(not Path('/sys/fs/cgroup/system.slice/agentporter-development.service').exists(), 'Service cgroup still exists')
    with sqlite3.connect('file:' + str(STATE / 'jobs.db') + '?mode=ro', uri=True) as db:
        require(db.execute("SELECT count(*) FROM jobs WHERE status IN ('running','cancelling','queued','cleanup_failed')").fetchone()[0] == 0, 'Nonterminal jobs')
        tables = {r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        require('job_admissions' not in tables or db.execute('SELECT count(*) FROM job_admissions').fetchone()[0] == 0, 'Unresolved admissions')


def rollback(config_fd, recovery_fd, uid, expected):
    receipt = json.loads(private_read(recovery_fd, 'receipt.json', uid))
    plan = receipt['plan']
    require(digest(canonical(plan)) == expected and set(plan['before']) == set(FILES + (HTTPS,)) and set(plan['after']) == set(FILES), 'Recovery plan hash/shape mismatch')
    require(digest(private_read(config_fd, HTTPS, uid)) == plan['before'][HTTPS], 'HTTPS changed; refuse rollback')
    old = {n: private_read(recovery_fd, n, uid) for n in FILES}
    current = {n: digest(private_read(config_fd, n, uid)) for n in FILES}
    require(all(digest(old[n]) == plan['before'][n] and current[n] in (plan['before'][n], plan['after'][n]) for n in FILES), 'Newer state or corrupt backup; refuse rollback')
    for name in FILES:
        if current[name] != plan['before'][name]:
            write(config_fd, name, old[name])
    write(recovery_fd, 'receipt.json', canonical({'state': 'rolled_back', 'plan': plan}) + b'\n')


def apply(config_fd, uid, inputs, output, plan, expected):
    require(digest(canonical(plan)) == expected, 'Review plan SHA mismatch')
    require(all(private_read(config_fd, n, uid) == inputs[n] for n in FILES + (HTTPS,)), 'Inputs changed since planning')
    os.mkdir(RECOVERY, 0o700, dir_fd=config_fd)
    recovery_fd = os.open(RECOVERY, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=config_fd)
    try:
        for name in FILES:
            write(recovery_fd, name, inputs[name], exclusive=True)
        write(recovery_fd, 'receipt.json', canonical({'state': 'prepared', 'plan': plan}) + b'\n', exclusive=True)
        os.fsync(config_fd)
        try:
            for name in FILES:
                require(private_read(config_fd, name, uid) == inputs[name], 'Input changed during application')
                write(config_fd, name, output[name])
            require(digest(private_read(config_fd, HTTPS, uid)) == plan['before'][HTTPS], 'HTTPS changed during application')
            write(recovery_fd, 'receipt.json', canonical({'state': 'applied', 'plan': plan}) + b'\n')
        except BaseException:
            rollback(config_fd, recovery_fd, uid, expected)
            raise
    finally:
        os.close(recovery_fd)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument('--plan', action='store_true')
    mode.add_argument('--apply', action='store_true')
    mode.add_argument('--rollback', action='store_true')
    parser.add_argument('--expected-plan-sha256')
    args = parser.parse_args()
    uid = pwd.getpwnam('agentporter-dev').pw_uid
    require(os.geteuid() == uid and uid != 0, 'Run only as agentporter-dev, never root')
    config_fd = open_directory(CONFIG, uid)
    try:
        if args.apply or args.rollback:
            require(args.expected_plan_sha256 and re.fullmatch('[0-9a-f]{64}', args.expected_plan_sha256), 'Supply independently reviewed plan SHA')
            quiet_and_stopped()
        if args.rollback:
            recovery_fd = open_directory(CONFIG / RECOVERY, uid)
            try:
                rollback(config_fd, recovery_fd, uid, args.expected_plan_sha256)
            finally:
                os.close(recovery_fd)
            print(json.dumps({'rolled_back': True, 'plan_sha256': args.expected_plan_sha256}))
            return
        release = CURRENT.resolve(strict=True)
        require(release.parent == Path('/opt/agentporter-development/versions') and re.fullmatch(r'\d{8}T\d{6}\.\d{6}Z', release.name), 'Unexpected installed release')
        inputs = {n: private_read(config_fd, n, uid) for n in FILES + (HTTPS,)}
        output, plan = transform(inputs, release)
        if args.apply:
            apply(config_fd, uid, inputs, output, plan, args.expected_plan_sha256)
        print(json.dumps({'applied': args.apply, 'plan_sha256': digest(canonical(plan)), 'plan': plan, 'recovery': str(CONFIG / RECOVERY)}, sort_keys=True))
    finally:
        os.close(config_fd)


if __name__ == '__main__':
    main()
