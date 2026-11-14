#!/usr/bin/env python3
"""Prepare generation 16 from sealed BCC packages plus this repair's exact source delta."""
import difflib
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tempfile

REPO = Path(__file__).resolve().parents[1]
OUT = REPO / 'artifacts/bcc-astra-fixes-20261113T232839Z/candidate16'
BASE = REPO / 'artifacts/bcc-astra-fixes-20261113T232839Z/baseline'
CHANGED = [
    'agents/credential_broker.py',
    'sandbox/workspace_transactions.py',
    'sandbox/git_snapshot.py',
    'sandbox/workspace_git_recovery.py',
]
EXPECTED = {'agentporter/' + name for name in CHANGED}


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def adapt(text):
    for old, new in [('codex_review', 'jax'), ('codex_impl', 'liz'), ('codex_research', 'prof')]:
        text = text.replace(old, new)
    return text


def source_preimage(name):
    path = BASE / ('src/agentporter/' + name)
    if path.exists():
        return path.read_text()
    return subprocess.check_output(
        ['git', 'show', 'HEAD:src/agentporter/' + name], cwd=REPO, text=True
    )


def main():
    if OUT.exists():
        raise FileExistsError(f'refusing to overwrite prepared candidate: {OUT}')
    OUT.mkdir(parents=True)
    manifest = {'generation': 16, 'roles': {}}
    for role in ('gateway', 'worker'):
        release = Path(f'/opt/agentporter-bcc/releases/consolidation-20261113-15-{role}')
        package = release / 'venv/lib/python3.13/site-packages/agentporter'
        target = OUT / role / 'agentporter'
        shutil.copytree(package, target, ignore=shutil.ignore_patterns('__pycache__'))
        for path in target.rglob('*'):
            if path.is_dir():
                path.chmod(0o755)
            elif path.is_file():
                path.chmod(0o644)
        target.chmod(0o755)

        for relative in CHANGED:
            before = adapt(source_preimage(relative)).splitlines(True)
            after = adapt((REPO / 'src/agentporter' / relative).read_text()).splitlines(True)
            if before == after:
                raise RuntimeError(f'{relative}: no repair delta exists against saved preimage')
            patch = ''.join(difflib.unified_diff(
                before, after, fromfile='a/' + relative, tofile='b/' + relative
            ))
            result = subprocess.run(
                ['patch', '--batch', '--forward', '--fuzz=0', '-p1'], input=patch, text=True,
                cwd=target, capture_output=True,
            )
            if result.returncode:
                raise RuntimeError(relative + ': ' + result.stdout + result.stderr)
            # Reverse only this source delta in a temporary package-shaped tree.
            # This proves the installed-only context survives without requiring
            # the installed module to equal the dirty source preimage.
            with tempfile.TemporaryDirectory(prefix='bcc-astra-reverse-') as temporary:
                reverse_root = Path(temporary)
                candidate_module = target / relative
                reverse_module = reverse_root / relative
                reverse_module.parent.mkdir(parents=True, exist_ok=True)
                reverse_module.write_bytes(candidate_module.read_bytes())
                reversed_patch = subprocess.run(
                    ['patch', '--batch', '--reverse', '--fuzz=0', '-p1'],
                    input=patch, text=True, cwd=reverse_root, capture_output=True,
                )
                if reversed_patch.returncode:
                    raise RuntimeError(relative + ' reverse: ' + reversed_patch.stdout + reversed_patch.stderr)
                original_installed = package / relative
                if reverse_module.read_bytes() != original_installed.read_bytes():
                    raise RuntimeError(relative + ': reverse patch did not restore sealed installed bytes')

        files = {}
        for path in target.rglob('*.py'):
            relative = path.relative_to(target).as_posix()
            installed = package / relative
            data = path.read_bytes()
            compile(data, str(path), 'exec')
            if not installed.exists() or installed.read_bytes() != data:
                files['agentporter/' + relative] = {
                    'before_sha256': sha(installed.read_bytes()) if installed.exists() else None,
                    'after_sha256': sha(data),
                }
        if set(files) != EXPECTED:
            raise RuntimeError(f'{role}: package delta outside exact allowlist: {sorted(files)}')
        manifest['roles'][role] = {
            'base_manifest_sha256': sha((release / 'RELEASE.json').read_bytes()),
            'files': files,
        }
    body = json.dumps(manifest, indent=2, sort_keys=True) + '\n'
    (OUT / 'MANIFEST.json').write_text(body)
    print(json.dumps({
        'candidate': str(OUT),
        'manifest_sha256': sha(body.encode()),
        'modules_per_role': len(EXPECTED),
        'roles': sorted(manifest['roles']),
    }, sort_keys=True))


if __name__ == '__main__':
    main()
