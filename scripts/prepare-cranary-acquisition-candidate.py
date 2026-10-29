#!/usr/bin/env python3
"""Prepare an inactive acquisition-only derivative of the reviewed v12 artifact.

Does not activate v17 hardening, change providers, install policy, use sudo or
restart anything. The working Wei-free repair is carried forward explicitly.
All other runtime fields and worker identities are preserved from pinned v12.
"""
import argparse
import difflib
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import tempfile
import types

REPO = Path(__file__).resolve().parents[1]
BASE = Path('/tmp/agentporter-development-candidate-v12.tgz')
BASE_SHA = 'e35b83635f96feb97b533709bbad1c7b5c4054bf6f9c8bcc7d51af8dacd664a5'


def load(name):
    path = REPO / 'scripts' / (name + '.py')
    module = types.ModuleType(name.replace('-', '_')); module.__file__ = str(path)
    exec(compile(path.read_bytes(), str(path), 'exec'), module.__dict__)
    return module


def once(text, before, after):
    if text.count(before) != 1:
        raise ValueError('Backport anchor is not unique')
    return text.replace(before, after, 1)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('output', 'report', 'extract-to', 'source-export'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--version', required=True)
    args = parser.parse_args()
    if os.geteuid() == 0 or not re.fullmatch(r'\d{8}T\d{6}\.\d{6}Z', args.version):
        raise PermissionError('Unprivileged preparation and explicit immutable version required')
    os.umask(0o077)
    for path in (args.output, args.report, args.extract_to, args.source_export):
        if path.exists() or path.is_symlink(): raise FileExistsError(path)
    overlay = load('prepare-development-overlay')
    builder = overlay.helper('build-development-candidate')
    installer = overlay.helper('install-development-artifact')
    packer = load('prepare-closeout-candidate')
    with tempfile.TemporaryDirectory(prefix='cranary-acquisition-build-') as temporary:
        temp = Path(temporary); base = temp / 'base.tgz'
        with BASE.open('rb') as source, base.open('xb') as target:
            shutil.copyfileobj(source, target, 1024 * 1024)
        if builder.digest(base, installer.LIMIT) != BASE_SHA: raise ValueError('Reviewed base changed')
        print('Verify pinned v12 payload', flush=True)
        original = temp / 'original'; overlay.extract(installer, base, original)
        release = original / 'release'; old = installer.bounded_json(original / 'release-files.json')
        installer.verify_release(release, old)
        metadata = installer.bounded_json(original / 'release-metadata.json')
        runtime_before = installer.bounded_json(original / 'runtime.json')
        previous = metadata['version']
        prefix = '/opt/agentporter-development/versions/'
        old_prefix, new_prefix = prefix + previous, prefix + args.version
        runtime = json.loads(json.dumps(runtime_before).replace(old_prefix, new_prefix))
        # Match the already active owner repair, never restore the paid Go route.
        runtime['workers']['wei'].update(provider='opencode', model='opencode/glm-5.3-flash-free',
            credentials={'.config/opencode/wei-key': '/var/lib/agentporter-dev/credentials/wei/.config/opencode/free-access'})

        payload = {name: (REPO / 'src/agentporter' / name).read_bytes() for name in (
            'https_download.py', 'action_policy.py', 'rest/schemas.py', 'rest/routers/exec.py')}
        # Keep v12's execution/resource path verbatim; only the policy prefix changes.
        scoped = (REPO / 'src/agentporter/scoped_https.py').read_text()
        baseline_scoped = (release / 'src/agentporter/scoped_https.py').read_text()
        boundary = '\nclass ScopedPublicHTTPS:\n'
        assert scoped.count(boundary) == baseline_scoped.count(boundary) == 1
        payload['scoped_https.py'] = (scoped.split(boundary)[0] + boundary + baseline_scoped.split(boundary)[1]).encode()
        baseline_server = (release / 'src/agentporter/server.py').read_text()
        server = once(baseline_server, '    scoped_https = ScopedPublicHTTPS(https_policy)\n',
            '    scoped_https = ScopedPublicHTTPS(https_policy)\n'
            '    from agentporter.https_download import create_https_download_tool\n'
            '    _https_download = create_https_download_tool(registry, https_policy, config.state_dir)\n')
        current = (REPO / 'src/agentporter/server.py').read_text()
        start = current.index('    @monitored_tool("https_download")')
        start = current.rfind('    @mcp.tool(', 0, start)
        end = current.index('    @monitored_tool("exec_run")', start)
        end = current.rfind('    @mcp.tool(', start, end)
        block = current[start:end]
        anchor = '    @monitored_tool("exec_run")'
        position = server.index(anchor); position = server.rfind('    @mcp.tool(', 0, position)
        server = server[:position] + block + server[position:]
        server = once(server, '            "exec_run": exec_run,',
                      '            "exec_run": exec_run,\n            "https_download": https_download,')
        server = once(server, '        return result\n\n    @mcp.tool()\n    @monitored_tool("list_workspaces")',
            '        if "cranary" in scopes and "downloads" in scopes["cranary"]:\n'
            '            result["scoped_public_https"]["downloads"] = dict(scopes["cranary"]["downloads"])\n'
            '        return result\n\n    @mcp.tool()\n    @monitored_tool("list_workspaces")')
        payload['server.py'] = server.encode()
        for name, data in payload.items():
            compile(data, name, 'exec')
            path = release / 'src/agentporter' / name
            if path.exists(): overlay.replace_file(path, data)
            else:
                mode = path.parent.stat().st_mode & 0o777; path.parent.chmod(mode | 0o200)
                try: path.write_bytes(data); path.chmod(0o444)
                finally: path.parent.chmod(mode)
        args.source_export.mkdir(mode=0o755)
        diffs = []
        for name, data in payload.items():
            path = args.source_export / name; path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data); path.chmod(0o444)
            # Base entries are available in the pinned archive; include the changed code diff.
            if name == 'server.py':
                diffs.extend(difflib.unified_diff(baseline_server.splitlines(True), server.splitlines(True),
                    fromfile='v12/server.py', tofile='acquisition/server.py'))
        (args.source_export / 'server-backport.patch').write_text(''.join(diffs))
        for name in ('venv/pyvenv.cfg', 'venv/lib/python3.13/site-packages/agentporter_development.pth'):
            path = release / name
            overlay.replace_file(path, path.read_bytes().replace(old_prefix.encode(), new_prefix.encode()))
        release.chmod(0o755); plan = release / 'operator-plan'; plan.mkdir()
        policy = (REPO / 'docs/examples/a7dev-cranary-acquisition-https.yaml').read_bytes()
        (plan / 'public-https.yaml.proposed').write_bytes(policy)
        overlay.replace_file(original / 'runtime.json', json.dumps(runtime, sort_keys=True).encode() + b'\n')
        metadata['version'] = args.version
        overlay.replace_file(original / 'release-metadata.json', json.dumps(metadata, sort_keys=True).encode() + b'\n')
        builder.freeze(release); manifest = builder.entries(release)
        changed = sorted(name for name in set(old) | set(manifest) if old.get(name) != manifest.get(name))
        allowed = {'src/agentporter/' + name for name in payload} | {
            'operator-plan/public-https.yaml.proposed', 'venv/pyvenv.cfg',
            'venv/lib/python3.13/site-packages/agentporter_development.pth'}
        assert set(changed) == allowed, 'Unrelated release payload changed'
        sources = {str(p.relative_to(release)): hashlib.sha256(p.read_bytes()).hexdigest()
                   for p in (release / 'src/agentporter').rglob('*') if p.is_file()}
        (args.source_export / 'source-manifest.json').write_text(json.dumps(sources, indent=2) + '\n')
        overlay.replace_file(original / 'release-files.json', json.dumps(manifest, sort_keys=True).encode() + b'\n')
        print('Pack acquisition-only candidate; all other v12 bytes preserved', flush=True)
        archive = temp / 'candidate.tgz'; packer.pack_canonical(builder, release, original, archive, manifest)
        overlay.extract(installer, archive, args.extract_to)
        installer.verify_release(args.extract_to / 'release', manifest)
        for name in ('runtime.json', 'release-metadata.json', 'release-files.json'):
            assert (original / name).read_bytes() == (args.extract_to / name).read_bytes()
        archive.chmod(0o400); os.link(archive, args.output)
        report = {'artifact': str(args.output), 'sha256': builder.digest(archive, installer.LIMIT),
            'version': args.version, 'base_sha256': BASE_SHA, 'profile': 'cranary-acquisition-only',
            'changed_release_files': changed, 'manifest_entries': len(manifest), 'source_sha256': sources,
            'runtime': runtime, 'proposed_policy_sha256': hashlib.sha256(policy).hexdigest(),
            'installed': False, 'independently_reviewed': False, 'v17_hardening_activated': False,
            'other_worker_profiles_changed': False, 'production_changed': False}
        with args.report.open('x') as stream: json.dump(report, stream, indent=2); stream.write('\n')
        print(json.dumps({key: report[key] for key in ('artifact', 'sha256', 'version', 'profile', 'installed', 'independently_reviewed')}))


if __name__ == '__main__': main()
