#!/usr/bin/env python3
"""Inspect active grant, or validate approved acquisition through actual A7Dev.

Default inspection never requests Posit or binary acquisition. --after requires
the exact owner grant, tests denials, acquires quarantined bytes, and runs the
existing offline population preview. No policy changes, sudo, restart or train.
"""
import argparse
import asyncio
import datetime
import importlib.util
import json
import os
from pathlib import Path
import re
import secrets
import tempfile

from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client
from mcp.shared._httpx_utils import create_mcp_http_client

spec = importlib.util.spec_from_file_location('old_https_acceptance',
    Path(__file__).with_name('verify-a7dev-cranary-https.py'))
helper = importlib.util.module_from_spec(spec); spec.loader.exec_module(helper)
POSIT = 'https://packagemanager.posit.co/cran/2021-06-30/src/contrib/PACKAGES.gz'
TCIU = 'https://cran.r-project.org/src/contrib/Archive/TCIU/TCIU_1.1.0.tar.gz'
TCIU_SHA = 'f9859ceb56997d30041c90f45073e59afd32f8ba985e0c6d500a6f49a2d98a42'
DIRECTORY = 'data-raw/cran-history/reports/2026-10-21-authorized-acquisition/downloads'
DEFAULT_PUBLIC_KEY_FILE = Path('/tmp/agentporter-development-asgard/config/secrets.env')
PREVIEW = 'data-raw/cran-history/reports/2026-10-19-laya-dataset-source-research/preview_historical_cran_population.py'


async def verify(after, output, *, public_key_file=DEFAULT_PUBLIC_KEY_FILE,
                 internal_key_file=None, expected_fingerprint=None):
    if after and (internal_key_file is None or not isinstance(expected_fingerprint, str)
            or not re.fullmatch('[0-9a-f]{64}', expected_fingerprint)):
        raise ValueError('--after requires --internal-key-file and the approved --expected-fingerprint')
    key = next(line.partition('=')[2].strip().strip('\"\'')
        for line in Path(public_key_file).read_text().splitlines()
        if line.startswith('AGENTPORTER_API_KEY='))
    internal_key = Path(internal_key_file).read_text().strip() if after else None
    if after and (not re.fullmatch('[A-Za-z0-9_-]{32,256}', internal_key) or internal_key == key):
        raise ValueError('A distinct private internal credential is required')
    records = []; nonce = secrets.token_hex(8)
    downloaded = []; bad_name = 'checksum-negative-' + nonce + '.tar.gz'
    async def call(session, name, args, endpoint):
        result = helper.unpack(await asyncio.wait_for(session.call_tool(name, args), 90))
        records.append({'endpoint': endpoint, 'tool': name, 'arguments': args, **result})
        (output / 'results.json').write_text(json.dumps(records, indent=2) + '\n')
        return result
    snapshots = []
    for endpoint in (helper.PUBLIC, helper.LOCAL):
        async with create_mcp_http_client(headers={'X-AgentPorter-Key': key,
                'X-Tunnel-Skip-AntiPhishing-Page': 'true'}) as client:
            client.follow_redirects = False
            async with streamable_http_client(endpoint, http_client=client) as streams:
                async with ClientSession(streams[0], streams[1]) as session:
                    await session.initialize()
                    cap = await call(session, 'get_capabilities', {}, endpoint)
                    deploy = await call(session, 'server_deploy_info', {}, endpoint)
                    assert not cap['is_error'] and not deploy['is_error']
                    scope = cap['data']['scoped_public_https']; snapshots.append((scope, deploy['data']))
                    assert scope['generic_shell_network'] is False and not deploy['data']['stale']
                    if after:
                        assert deploy['data']['loaded_fingerprint'] == expected_fingerprint
                        assert deploy['data']['disk_fingerprint'] == expected_fingerprint
                    if not after or endpoint != helper.PUBLIC: continue
                    assert set(scope['hosts']) == helper.HOSTS | {'packagemanager.posit.co'}
                    assert scope['workspaces'] == ['cranary'] and set(scope['methods']) == {'GET', 'HEAD'}
                    downloads = dict(scope['downloads'])
                    if 'cran_all_paths' in downloads:
                        assert type(downloads.pop('cran_all_paths')) is bool
                    assert downloads == {'hosts': ['cran.r-project.org', 'packagemanager.posit.co'],
                        'directory': DIRECTORY, 'max_response_bytes': 16777216, 'timeout_seconds': 60}
                    for args in [
                        {'workspace_id': 'agentporter-dev', 'url': POSIT, 'filename': 'wrong-workspace.gz'},
                        {'workspace_id': 'cranary', 'url': 'https://example.com/x', 'filename': 'wrong-host.gz'},
                        {'workspace_id': 'cranary', 'url': POSIT.replace('https:', 'http:'), 'filename': 'wrong-scheme.gz'},
                        {'workspace_id': 'cranary', 'url': POSIT, 'filename': '../escape'},
                        {'workspace_id': 'cranary', 'url': POSIT, 'filename': 'over-cap.gz', 'max_bytes': 16777217},
                        {'workspace_id': 'cranary', 'url': POSIT, 'filename': 'over-time.gz', 'timeout_seconds': 61},
                        {'workspace_id': 'cranary', 'url': POSIT.replace('.co/', '.co:444/'), 'filename': 'wrong-port.gz'},
                        {'workspace_id': 'cranary', 'url': POSIT.replace('packagemanager.posit.co', '169.254.169.254'), 'filename': 'metadata.gz'},
                        {'workspace_id': 'cranary', 'url': POSIT.replace('2021-06-30', 'latest'), 'filename': 'latest.gz'},
                        {'workspace_id': 'cranary', 'url': POSIT + '?redirect=https://example.com', 'filename': 'query.gz'},
                    ]:
                        assert (await call(session, 'https_download', args, endpoint))['is_error']
                    for argv in (['curl', '-X', 'POST', POSIT], ['curl', '-L', POSIT],
                                 ['sh', '-c', 'curl ' + POSIT]):
                        assert (await call(session, 'exec_run', {'workspace_id': 'cranary', 'argv': argv,
                            'network_access': True, 'timeout_seconds': 15}, endpoint))['is_error']
                    # v17 public scope denies ordinary execution, even on loopback.
                    assert (await call(session, 'exec_run', {'workspace_id': 'cranary',
                        'argv': ['true'], 'network_access': False}, endpoint))['is_error']
                    for url, name, expected in ((POSIT, 'PACKAGES-' + nonce + '.gz', None),
                                              (TCIU, 'TCIU-1.1.0-' + nonce + '.tar.gz', TCIU_SHA)):
                        result = await call(session, 'https_download', {'workspace_id': 'cranary', 'url': url,
                            'filename': name, 'expected_sha256': expected}, endpoint)
                        assert not result['is_error'], result
                        data = result['data']; assert data['http_status'] == 200 and data['bytes'] <= 16777216
                        assert data['expected_sha256_verified'] is (expected is not None)
                        assert not data['training_eligible'] and not data['historical_identity_verified']
                        assert data['path'] == DIRECTORY + '/' + name and data['source_url'] == url
                        assert re.fullmatch('[0-9a-f]{64}', data['sha256'])
                        if expected: assert data['sha256'] == expected
                        downloaded.append(data)
                    result = await call(session, 'https_download', {'workspace_id': 'cranary',
                        'url': 'https://cran.r-project.org/src/contrib/Archive/ebmc/ebmc_1.0.0.tar.gz',
                        'filename': bad_name, 'expected_sha256': '0' * 64}, endpoint)
                    assert result['is_error']
                    listing = await call(session, 'list_files', {'workspace_id': 'cranary',
                        'path': DIRECTORY, 'depth': 1}, endpoint)
                    assert not listing['is_error'] and isinstance(listing['data'], list)
                    assert all(isinstance(p, str) and Path(p).name != bad_name for p in listing['data'])
    assert snapshots[0][0] == snapshots[1][0]
    assert snapshots[0][1]['pid'] == snapshots[1][1]['pid']
    assert snapshots[0][1]['loaded_fingerprint'] == snapshots[1][1]['loaded_fingerprint']
    if after:
        # The private credential is sent ONLY to the literal direct-loopback
        # endpoint. It is never included in records, output or tunnel headers.
        async with create_mcp_http_client(headers={'X-AgentPorter-Key': internal_key}) as client:
            client.follow_redirects = False
            async with streamable_http_client(helper.LOCAL, http_client=client) as streams:
                async with ClientSession(streams[0], streams[1]) as session:
                    await session.initialize()
                    deploy = await call(session, 'server_deploy_info', {}, helper.LOCAL)
                    assert not deploy['is_error'] and deploy['data']['pid'] == snapshots[0][1]['pid']
                    assert deploy['data']['loaded_fingerprint'] == expected_fingerprint and not deploy['data']['stale']
                    # Independently rehash saved bytes inside the offline sandbox.
                    code = ('import hashlib,json; from pathlib import Path; '
                        'receipts=' + repr(downloaded) + '; '
                        'assert not Path(' + repr(DIRECTORY + '/' + bad_name) + ').exists(); '
                        'assert all(Path(r["path"]).stat().st_size==r["bytes"] and r["bytes"]<=16777216 '
                        'and hashlib.sha256(Path(r["path"]).read_bytes()).hexdigest()==r["sha256"] for r in receipts); '
                        'print(json.dumps({"saved_bytes_verified":True,"consumer_sha256":hashlib.sha256(Path(' +
                        repr(PREVIEW) + ').read_bytes()).hexdigest()}))')
                    result = await call(session, 'exec_run', {'workspace_id': 'cranary', 'network_access': False,
                        'argv': ['python3', '-I', '-c', code], 'timeout_seconds': 15}, helper.LOCAL)
                    assert not result['is_error'] and result['data']['exit_code'] == 0, result
                    consumer = json.loads(result['data']['stdout'])
                    preview_path = DIRECTORY.rsplit('/', 1)[0] + '/population-preview-' + nonce + '.json'
                    result = await call(session, 'exec_run', {'workspace_id': 'cranary', 'network_access': False,
                        'argv': ['python3', '-B', PREVIEW, '--input', downloaded[0]['path'], '--source-url', POSIT,
                                 '--snapshot-date', '2021-06-30', '--output', preview_path],
                        'timeout_seconds': 30}, helper.LOCAL)
                    assert not result['is_error'] and result['data']['exit_code'] == 0, result
                    code = ('import json,hashlib; from pathlib import Path; p=Path(' + repr(preview_path) + '); '
                        'assert p.stat().st_size<=16777216; b=p.read_bytes(); d=json.loads(b); '
                        'assert d["input_sha256"]==' + repr(downloaded[0]['sha256']) + '; '
                        'assert d["population_size_candidate"]>=1000 and d["selected_count"]==20; '
                        'assert all(d[k] is False for k in ("training_eligible","evaluation_eligible",'
                        '"rights_cleared","historical_frame_complete_verified")); '
                        'print(json.dumps({"path":str(p),"sha256":hashlib.sha256(b).hexdigest(),'
                        '"population_size_candidate":d["population_size_candidate"],'
                        '"decompressed_sha256":d["decompressed_sha256"],"training_eligible":False}))')
                    result = await call(session, 'exec_run', {'workspace_id': 'cranary', 'network_access': False,
                        'argv': ['python3', '-I', '-c', code], 'timeout_seconds': 15}, helper.LOCAL)
                    assert not result['is_error'] and result['data']['exit_code'] == 0, result
                    preview_receipt = json.loads(result['data']['stdout'])
                    (output / 'acquisition-receipts.json').write_text(json.dumps({'downloads': downloaded,
                        'population_preview': preview_receipt, **consumer}, indent=2) + '\n')
    summary = {'public_local_same_process': True, 'after': after, 'scope': snapshots[0][0],
                      'loaded_fingerprint': snapshots[0][1]['loaded_fingerprint'],
                      'installed_acceptance': 'passed' if after else 'not attempted; inspection only'}
    (output / 'summary.json').write_text(json.dumps(summary, indent=2) + '\n')
    print(json.dumps(summary))


def main():
    parser = argparse.ArgumentParser(description=__doc__); parser.add_argument('--after', action='store_true')
    parser.add_argument('--public-key-file', type=Path, default=DEFAULT_PUBLIC_KEY_FILE)
    parser.add_argument('--internal-key-file', type=Path)
    parser.add_argument('--expected-fingerprint')
    args = parser.parse_args(); os.umask(0o077)
    output = Path(tempfile.mkdtemp(prefix='a7dev-cranary-acquisition-verification-'))
    print('Private evidence: ' + str(output), flush=True)
    asyncio.run(verify(args.after, output, public_key_file=args.public_key_file,
        internal_key_file=args.internal_key_file, expected_fingerprint=args.expected_fingerprint))


if __name__ == '__main__': main()
