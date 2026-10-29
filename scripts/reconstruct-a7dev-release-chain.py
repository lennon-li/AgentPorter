#!/usr/bin/env python3
"""Read-only verification of the recovered development release chain.

Never invokes installer verification (which chmods directories), imports release
code, reads credentials, or changes installed files. Output is sanitized hashes.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import stat


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def inventory(root):
    result = {}
    for directory, dirs, files in os.walk(root, followlinks=False):
        dirs[:] = sorted(d for d in dirs if d != '__pycache__')
        for name in sorted(dirs + files):
            path = Path(directory) / name
            info = path.lstat()
            relative = path.relative_to(root).as_posix()
            if stat.S_ISLNK(info.st_mode):
                result[relative] = {'link': os.readlink(path)}
            elif stat.S_ISREG(info.st_mode):
                result[relative] = {'sha256': digest(path), 'executable': bool(info.st_mode & 0o111)}
            elif not stat.S_ISDIR(info.st_mode):
                raise ValueError('special release entry')
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    base = Path('/opt/agentporter-development/versions')
    previous = base / '20261022T224004.423620Z'
    repaired = base / '20261024T011308.040822Z'
    diagnostic = base / '20261024T021629.107191Z'
    current = base.parent / 'current'
    before = current.resolve(strict=True)
    baseline = Path('/tmp/prof-a7dev-posit-redirect-diagnostic-20261022/extracted')
    assert json.loads((baseline / 'release-metadata.json').read_text())['version'] == previous.name
    candidate = Path('/home/operator/repos/AgentPorter/development-candidates/a7dev-smoke-20261023')
    receipt = Path('/home/operator/repos/Qman/docs/evidence/a7dev-live-repair-20261023/activation.json')
    diagnostic_receipt = Path('/home/operator/repos/Qman/docs/evidence/a7dev-pickup-20261024/diagnostic-activation.json')
    manifest_path = candidate / 'manifest.json'
    manifest = json.loads(manifest_path.read_text())
    activation = json.loads(receipt.read_text())
    assert digest(manifest_path) == activation['manifest_sha256'] == 'c086aedae4197974bb2e6b8db6721529325a444eaed4b139072e6da72ff56789'
    expected = json.loads((baseline / 'release-files.json').read_text())
    report = {'captured_at_utc': datetime.now(timezone.utc).isoformat(),
              'current_before': str(before), 'read_only': True, 'releases': {},
              'evidence_hashes': {str(p): digest(p) for p in (manifest_path, receipt, diagnostic_receipt)},
              'limits': ['Public reconstructed receipts are mutable, not an original root-private installer receipt.',
                         'Ownership inside sandbox is remapped; native host metadata must be checked separately.',
                         'Policies, process-loaded bytes and rollback execution are not verified by this script.']}
    for root in (previous, repaired, diagnostic):
        admitted = dict(expected)
        if root != previous:
            for rel, pins in manifest['files'].items():
                assert digest(candidate / 'src' / rel) == pins['candidate_sha256']
                admitted['src/' + rel] = {'sha256': pins['candidate_sha256'], 'executable': False}
            pth = 'venv/lib/python3.13/site-packages/agentporter_development.pth'
            admitted[pth] = {'sha256': hashlib.sha256((str(root / 'src') + '\n').encode()).hexdigest(), 'executable': False}
        if root == diagnostic:
            admitted['src/agentporter/agents/provider_egress.py'] = {
                'sha256': '4bdaef30e9570c6abbabe7b77cfad7379f862dcecdb199a3cd2805c8532e2bf6', 'executable': False}
        actual = inventory(root)
        missing = sorted(set(admitted) - set(actual))
        extra = sorted(set(actual) - set(admitted))
        changed = sorted(k for k in set(actual) & set(admitted) if actual[k] != admitted[k])
        report['releases'][root.name] = {'entries': len(actual), 'missing': missing,
            'extra': extra, 'unexpected_changes': changed,
            'manifest_match': not (missing or extra or changed),
            'inventory_sha256': hashlib.sha256(json.dumps(actual, sort_keys=True, separators=(',', ':')).encode()).hexdigest()}
        print(json.dumps({'release': root.name, **report['releases'][root.name]}), flush=True)
    report['current_after'] = str(current.resolve(strict=True))
    report['current_stable'] = report['current_before'] == report['current_after']
    with args.output.open('x') as stream:
        json.dump(report, stream, indent=2, sort_keys=True)
        stream.write('\n')
    return 0 if report['current_stable'] and all(r['manifest_match'] for r in report['releases'].values()) else 1


if __name__ == '__main__':
    raise SystemExit(main())
