#!/usr/bin/env python3
"""Prepare BCC staging data unprivileged; never install or start a service."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import stat
import tarfile

import yaml


CODEX = Path('/home/yeli/.codex-liz/packages/app-server-daemon/releases/0.164.0-x86_64-unknown-linux-musl/bin')
BINARIES = {
    'codex/codex': CODEX / 'codex',
    'codex/codex-code-mode-host': CODEX / 'codex-code-mode-host',
    'ming/claude': Path('/home/yeli/.local/share/claude/versions/2.1.287'),
    'phil/copilot': Path('/home/yeli/.local/lib/node_modules/@github/copilot/node_modules/@github/copilot-linux-x64/copilot'),
    'wei/opencode': Path('/home/yeli/.local/lib/node_modules/opencode-ai/node_modules/opencode-linux-x64/bin/opencode'),
    'argie/agy': Path('/home/yeli/.local/bin/agy'),
}


def digest(path):
    result = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            result.update(block)
    return result.hexdigest()


def prepare(output, venv, version):
    if os.geteuid() == 0:
        raise PermissionError('Build staging artifacts unprivileged')
    if not re.fullmatch(r'bcc-stage-[0-9]{8}-[0-9]{2}', version):
        raise ValueError('Explicit BCC staging version required')
    output.mkdir(parents=True, mode=0o700)
    if list(output.iterdir()):
        raise ValueError('Use an empty output directory')
    os.chmod(output, 0o700)
    installed = Path('/opt/agentporter-bcc/releases') / version
    data = Path('/var/lib/agentporter-bcc-worker/staging') / version
    release = output / 'release'
    release.mkdir()
    shutil.copytree(venv, release / 'venv', symlinks=True,
                    ignore=shutil.ignore_patterns('__pycache__', '*.pyc'))
    # Scripts with builder-local shebangs are unnecessary: use venv/bin/python -I.
    for path in (release / 'venv/bin').iterdir():
        if path.name not in {'python', 'python3', 'python3.13'}:
            path.unlink()
    binary_inputs = {}
    for relative, source in BINARIES.items():
        source = source.resolve(strict=True)
        with source.open('rb') as stream:
            if stream.read(4) != b'\x7fELF':
                raise ValueError(f'Expected standalone native executable: {relative}')
        before = digest(source)
        target = release / 'cli' / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target)
        target.chmod(0o555)
        if digest(target) != before or digest(source) != before:
            raise ValueError('Executable changed during packaging')
        binary_inputs[relative] = {'source': str(source), 'sha256': before}
    workers = {}
    copies = []
    for name, home in [('jax', '.codex'), ('liz', '.codex-liz'), ('prof', '.codex-prof')]:
        credentials = {'.codex/auth.json': str(data / 'credentials' / name / '.codex/auth.json'),
                       '.codex/config.toml': str(data / 'credentials' / name / '.codex/config.toml')}
        workers[name] = {'executable': str(installed / 'cli/codex/codex'),
                         'code_mode_host': str(installed / 'cli/codex/codex-code-mode-host'),
                         'credentials': credentials,
                         'codex_config': credentials['.codex/config.toml']}
        for target, source_name in [('.codex/auth.json', 'auth.json'), ('.codex/config.toml', 'config.toml')]:
            copies.append({'source': f'/home/yeli/{home}/{source_name}',
                           'destination': str(data / 'credentials' / name / target)})
    for name, binary, target, source in [
        ('ming', 'ming/claude', '.claude/.credentials.json', '/home/yeli/.claude/.credentials.json'),
        ('phil', 'phil/copilot', '.copilot-phil/config.json', '/home/yeli/.copilot-phil/config.json'),
        ('wei', 'wei/opencode', '.config/opencode/wei-key', '/home/yeli/.config/opencode/wei-key'),
        ('argie', 'argie/agy', '.gemini/antigravity-cli/antigravity-oauth-token', '/home/yeli/.gemini/antigravity-cli/antigravity-oauth-token'),
    ]:
        destination = str(data / 'credentials' / name / target)
        workers[name] = {'executable': str(installed / 'cli' / binary), 'credentials': {target: destination}}
        copies.append({'source': source, 'destination': destination})
    workers['wei'].update(provider='opencode', model='opencode/glm-5.3-flash-free')
    workspace = str(data / 'fixture')
    runtime = {'enabled': True, 'profile': 'development', 'gateway_user': 'agentporter-bcc-worker',
               'production_uid': 2056259175, 'sandbox_executable': '/opt/agentporter-bcc/bin/bwrap',
               'network_enabled': True, 'egress_policy': 'provider_origin',
               'parallel_search_enabled': False, 'public_client_policy_required': True,
               'allowed_workspace_roots': [{'path': workspace, 'writable': True}],
               'job_resources': {'memory_bytes': 2 * 1024**3, 'pids': 128,
                                 'cpu_quota_us': 200000, 'cpu_period_us': 100000},
               'workers': workers}
    templates = output / 'templates'
    templates.mkdir()
    documents = {
        'config.yaml': {'server': {'host': '127.0.0.1', 'port': 8876, 'name': 'BCC isolated staging'},
                        'security': {'auth': 'api_key'}, 'sandbox': {'network': False}},
        'workspaces.yaml': {'workspaces': {'bcc-staging': {'path': workspace, 'writable': True,
                           'allow_execute': True, 'allow_agent_dispatch': True}}},
        'public-client-policy.yaml': {'version': 1, 'workspaces': {'bcc-staging': {
            'path': workspace, 'operations': ['read', 'write', 'exec', 'git_read', 'git_fetch', 'dispatch', 'dispatch_write']}}},
        'development-runtime.yaml': runtime,
    }
    for name, document in documents.items():
        (templates / name).write_text(yaml.safe_dump(document, sort_keys=True))
    private = output / 'private'
    private.mkdir(mode=0o700)
    for name, value in [('secrets.env', 'AGENTPORTER_API_KEY=' + secrets.token_urlsafe(32) + '\n'),
                        ('internal-client.key', secrets.token_urlsafe(32) + '\n')]:
        (private / name).write_text(value)
        (private / name).chmod(0o600)
    unit = f'''[Unit]
Description=BCC isolated AgentPorter staging workers
After=network.target

[Service]
Type=simple
User=agentporter-bcc-worker
Group=agentporter-bcc-worker
UMask=0077
WorkingDirectory={data}/home
Environment=HOME={data}/home
Environment=PATH=/usr/bin:/bin
Environment=AGENTPORTER_CONFIG_DIR={data}/config
Environment=AGENTPORTER_STATE_DIR={data}/state
Environment=AGENTPORTER_CACHE_DIR={data}/cache
Environment=PYTHONDONTWRITEBYTECODE=1
UnsetEnvironment=PYTHONPATH PYTHONHOME PYTHONSTARTUP PYTHONUSERBASE LD_PRELOAD LD_LIBRARY_PATH AGENTPORTER_API_KEY
ExecStart={installed}/venv/bin/python -I -m agentporter.resource_supervisor --config-dir {data}/config
Delegate=yes
MemoryMax=8G
MemorySwapMax=0
CPUQuota=400%
TasksMax=512
KillMode=control-group
TimeoutStopSec=15
Restart=no
NoNewPrivileges=yes
PrivateTmp=yes
ProtectHome=yes
'''
    (output / 'agentporter-bcc-worker.service').write_text(unit)
    manifest = {}
    for path in sorted(release.rglob('*')):
        relative = str(path.relative_to(release))
        if path.is_symlink():
            target = os.readlink(path)
            if relative not in {'venv/bin/python', 'venv/bin/python3', 'venv/bin/python3.13', 'venv/lib64'}:
                raise ValueError('Unexpected release symlink: ' + relative)
            manifest[relative] = {'symlink': target}
        elif path.is_file():
            manifest[relative] = {'sha256': digest(path)}
    (release / 'RELEASE.json').write_text(json.dumps({'version': version, 'files': manifest,
        'binary_inputs': binary_inputs}, sort_keys=True, indent=2) + '\n')
    archive = output / 'release.tar.gz'
    with tarfile.open(archive, 'w:gz', dereference=False, compresslevel=1) as bundle:
        for path in sorted(release.rglob('*')):
            bundle.add(path, arcname=str(path.relative_to(release)), recursive=False)
    (output / 'credential-copies.json').write_text(json.dumps(copies, indent=2) + '\n')
    checksums = {str(path.relative_to(output)): digest(path) for path in sorted(output.rglob('*'))
                 if path.is_file() and not path.is_relative_to(release)}
    (output / 'INPUTS.json').write_text(json.dumps({'version': version, 'installed_release': str(installed),
        'data': str(data), 'sha256': checksums}, sort_keys=True, indent=2) + '\n')
    installer = Path(__file__).with_name('bcc-staging-installer.py.in').read_text()
    installer = installer.replace('@@SOURCE@@', repr(str(output)))
    installer = installer.replace('@@INPUTS@@', repr(json.loads((output / 'INPUTS.json').read_text())))
    installer = installer.replace('@@CREDENTIALS@@', repr(copies))
    (output / 'install-bcc-staging.py').write_text(installer)
    (output / 'installer.sha256').write_text(digest(output / 'install-bcc-staging.py') + '\n')
    print(json.dumps({'version': version, 'output': str(output), 'archive_sha256': digest(archive),
                      'release_files': len(manifest), 'provider_credentials_copied': False}))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--venv', type=Path, required=True)
    parser.add_argument('--version', required=True)
    args = parser.parse_args()
    prepare(args.output.resolve(), args.venv.resolve(), args.version)
