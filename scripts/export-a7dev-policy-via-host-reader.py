#!/usr/bin/env python3
"""Sanitized read-only policy projection using existing sudo tail/rsync grants.

Runs as the ordinary owner, never root. Raw bytes stay in memory. Reuses only
the pure projection body of the historical exporter; service-UID acquisition
and its identity checks are not invoked or modified. No policy apply capability.
"""
import argparse
import ast
import hashlib
import json
import os
from pathlib import Path
import pwd
import runpy
import subprocess

SOURCE = Path(__file__).resolve().parents[1] / 'docs/evidence/a7dev-v4-admission-20261023/policy-readonly-export.py'
CONFIG = Path('/var/lib/agentporter-dev/config')


def command(*args):
    return subprocess.run(['sudo', '-n', '/usr/bin/' + args[0], *args[1:]],
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=15)


def acquire(name):
    path = str(CONFIG / name)
    info = command('rsync', '-an', '--itemize-changes',
                   '--out-format=%i|%U|%G|%l|%M|%n', path,
                   '/tmp/prof-a7dev-policy-never-created')
    if info.returncode:
        if b'No such file or directory' in info.stderr:
            return None, {'present': False}
        raise ValueError('metadata read failed')
    fields = info.stdout.decode().strip().split('|')
    if len(fields) != 6 or fields[5] != name or fields[0][1] != 'f':
        raise ValueError('unexpected metadata')
    uid, size = int(fields[1]), int(fields[3])
    if uid != pwd.getpwnam('agentporter-dev').pw_uid or size > 1024 * 1024:
        raise ValueError('unsafe policy owner/size')
    mode = command('rsync', '--list-only', '--numeric-ids', path)
    if mode.returncode or not mode.stdout.startswith(b'-rw------- '):
        raise ValueError('unsafe policy type/mode')
    raw = command('tail', '-c', '1048577', '--', path)
    if raw.returncode or len(raw.stdout) != size:
        raise ValueError('bounded read failed')
    return raw.stdout, {'present': True, 'uid': uid, 'mode': '0o600',
                        'size_bytes': size, 'sha256': hashlib.sha256(raw.stdout).hexdigest(),
                        'source_mtime_seconds': fields[4]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if os.geteuid() != pwd.getpwnam('operator').pw_uid:
        raise ValueError('ordinary owner identity required')
    if args.output.exists():
        raise ValueError('output already exists')
    source = SOURCE.read_bytes()
    namespace = runpy.run_path(str(SOURCE), run_name='policy_projection_library')
    tree = ast.parse(source)
    original = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'main')
    assert len(original.body) == 32
    assert ast.unparse(original.body[2]).startswith('docs = ')
    assert isinstance(original.body[30], ast.For) and ast.unparse(original.body[30].target) == 'name'
    # Only validation and sanitized projection, no acquisition or UID alteration.
    function = ast.FunctionDef(name='project', args=ast.arguments(posonlyargs=[],
        args=[ast.arg(arg='docs')], kwonlyargs=[], kw_defaults=[], defaults=[]),
        body=original.body[3:30] + [ast.Return(value=ast.Name(id='result', ctx=ast.Load()))],
        decorator_list=[])
    module = ast.fix_missing_locations(ast.Module(body=[function], type_ignores=[]))
    exec(compile(module, str(SOURCE) + ':pure-projection', 'exec'), namespace)
    before = (CONFIG.parent, Path('/opt/agentporter-development/current').resolve(strict=True))
    bodies, docs, metadata = {}, {}, {}
    for name in namespace['FILES']:
        body, info = acquire(name)
        bodies[name], metadata[name] = body, info
        if body is None:
            docs[name] = None
            continue
        if any(isinstance(t, (namespace['yaml'].tokens.AliasToken, namespace['yaml'].tokens.AnchorToken))
               for t in namespace['yaml'].scan(body)):
            raise ValueError('YAML aliases unsupported')
        value = namespace['yaml'].load(body, Loader=namespace['UniqueLoader'])
        if value is not None and not isinstance(value, dict):
            raise ValueError('nonmapping policy')
        docs[name] = value or {}
    namespace['METADATA'] = metadata
    result = namespace['project'](docs)
    for name in namespace['FILES']:
        body, info = acquire(name)
        if body != bodies[name] or info != metadata[name]:
            raise ValueError('policy changed during snapshot')
    if Path('/opt/agentporter-development/current').resolve(strict=True) != before[1]:
        raise ValueError('release changed during snapshot')
    result.update(acquisition='ordinary owner; existing sudo tail and rsync read-only grants',
                  projection_source_sha256=hashlib.sha256(source).hexdigest(),
                  metadata_limitation='No inode/ctime/link-count or no-follow ancestor proof; native service-UID exporter still required before apply.')
    with args.output.open('x') as stream:
        json.dump(result, stream, indent=2, sort_keys=True)
        stream.write('\n')
    args.output.chmod(0o600)
    print(json.dumps({'output': str(args.output), 'workspaces': len(result['workspace_rows']),
                      'current_release': result['current_release'], 'policy_changed': False}))


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        print(json.dumps({'status': 'NOT VERIFIED', 'error_type': type(error).__name__,
                          'reason': 'Read-only host projection failed; raw data and diagnostics suppressed.'}))
        raise SystemExit(1)
