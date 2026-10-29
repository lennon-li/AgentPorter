#!/usr/bin/env python3
"""Streaming delta check against exact v17-r3; no payload extraction/execution.

An implementer-authored cross-check, not independent security clearance.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import types

BASE_SHA = 'a1b91f9f15a44cc5e9ecbb265b73f17f47472b028b0009468e84b379d6340dac'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('artifact', 'base-artifact', 'input-pins', 'report'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--sha256', required=True);args = parser.parse_args()
    if os.geteuid() == 0:raise PermissionError('Unprivileged cross-check only')
    helper = Path(__file__).with_name('audit-cranary-acquisition-candidate.py')
    data = helper.read_bytes()
    if hashlib.sha256(data).hexdigest() != '1dc2401c7687d1327ed1382192cd0b4b21b5429983bdda5fd27393a1e6ae7f16':raise ValueError('Inspector changed')
    inspector = types.ModuleType('pinned_archive_inspector');inspector.__file__ = str(helper)
    exec(compile(data, str(helper), 'exec'), inspector.__dict__)
    old, before, _, _ = inspector.inspect(args.base_artifact, BASE_SHA)
    files, docs, sources, total = inspector.inspect(args.artifact, args.sha256)
    modules = {'src/agentporter/' + name for name in ('action_policy.py', 'client_policy.py',
        'https_download.py', 'rest/routers/exec.py', 'rest/schemas.py', 'scoped_https.py', 'server.py')}
    plan = {'docs/examples/a7dev-cranary-acquisition-https.yaml': 'operator-plan/public-https.yaml.proposed',
        'scripts/verify-a7dev-cranary-acquisition.py': 'operator-plan/verify-a7dev-cranary-acquisition.py',
        'scripts/verify-a7dev-cranary-https.py': 'operator-plan/verify-a7dev-cranary-https.py'}
    expected = modules | set(plan.values()) | {'venv/pyvenv.cfg', 'venv/lib/python3.13/site-packages/agentporter_development.pth'}
    changed = {name for name in set(old) | set(files) if old.get(name) != files.get(name)}
    assert changed == expected, 'Unrelated payload delta'
    version = docs['release-metadata.json']['version'];previous = before['release-metadata.json']['version']
    metadata = dict(before['release-metadata.json']);metadata['version'] = version
    assert metadata == docs['release-metadata.json']
    prefix = '/opt/agentporter-development/versions/'
    runtime = json.loads(json.dumps(before['runtime.json']).replace(prefix + previous, prefix + version))
    assert runtime == docs['runtime.json'], 'Runtime changes beyond version relocation'
    assert runtime['egress_policy'] == 'provider_origin' and runtime['public_client_policy_required'] is True
    assert 'job_resources' in runtime and runtime['workers']['wei']['model'] == 'opencode/glm-5.3-flash-free'
    pins = json.loads(args.input_pins.read_text())
    assert {name: pins[name] for name in pins if name.startswith('src/agentporter/')} == {
        name: hashlib.sha256(body).hexdigest() for name, body in sources.items()}
    for name, target in plan.items():assert files[target]['sha256'] == pins[name]
    assert files['operator-plan/public-https.yaml.proposed']['sha256'] == 'e036dbeb156f05e6ad061cabe2aea646e255a4f95b0efbd08f648bfa901d6fcf'
    fp = hashlib.sha256()
    for name, body in sorted(sources.items()):fp.update(name.removeprefix('src/agentporter/').encode()+b'\0'+body+b'\0')
    report = {'passed': True, 'archive_sha256': args.sha256, 'base_sha256': BASE_SHA,
        'manifest_entries': len(files), 'source_files': len(sources), 'expanded_bytes': total,
        'package_fingerprint': fp.hexdigest(), 'version': version, 'changed_release_files': sorted(changed),
        'v17_runtime_controls_retained': True, 'payload_executed': False, 'installed': False,
        'independently_reviewed': False}
    with args.report.open('x') as stream:json.dump(report, stream, indent=2);stream.write('\n')
    print(json.dumps(report))


if __name__ == '__main__':main()
