#!/usr/bin/env python3
"""Public/local acceptance for the bounded acquisition repair; never installs.

Writes only a fresh approved Cranary acquisition and a private local evidence
directory. Does not authenticate historical package identity or train anything.
"""
import argparse
import asyncio
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import tempfile

from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client
from mcp.shared._httpx_utils import create_mcp_http_client
from mcp.types import PaginatedRequestParams

PUBLIC = 'https://example-8765.use.devtunnels.ms/mcp'
LOCAL = 'http://127.0.0.1:8876/mcp'
URL = 'https://packagemanager.posit.co/cran/2022-06-30/src/contrib/PACKAGES.gz'
DIRECTORY = 'data-raw/cran-history/reports/2026-10-21-authorized-acquisition/downloads/'
EXPECTED = 'd2cd86e52af94510adf4e9aed96d4cc7b4172a5a93c3ba0e0094569bf93e4c52'
PROTECTED = {'obsidian', 'agentporter', 'AgentPorter', 'asgard-hermes-review', 'repos'}


def unpack(result):
    data = result.structured_content
    if data is None:
        raw = ''.join(item.text for item in result.content if item.type == 'text')
        try:
            data = json.loads(raw)
        except ValueError:
            data = {'message': raw}
    if isinstance(data, dict) and set(data) == {'result'}:
        data = data['result']
    return {'is_error': result.is_error, 'data': data}


async def verify(args, key, output):
    record = {'passed': False, 'timestamp': datetime.datetime.now(datetime.timezone.utc).isoformat(),
              'discoveries': [], 'checks': [], 'denials': [],
              'historical_identity_verified': False, 'training_eligible': False,
              'expected_checksum_basis': 'Earlier verified acquisition; not an independent publisher attestation'}

    def save():
        (output / 'results.json').write_text(json.dumps(record, indent=2) + '\n')

    try:
        for endpoint in (PUBLIC, LOCAL):
            async with create_mcp_http_client(headers={
                    'X-AgentPorter-Key': key, 'X-Tunnel-Skip-AntiPhishing-Page': 'true'}) as client:
                client.follow_redirects = False
                async with streamable_http_client(endpoint, http_client=client) as streams:
                    async with ClientSession(streams[0], streams[1]) as session:
                        await session.initialize()

                        async def call(name, arguments):
                            return unpack(await asyncio.wait_for(session.call_tool(name, arguments), 95))

                        async def good(name, arguments):
                            result = await call(name, arguments)
                            if result['is_error']:
                                raise AssertionError('MCP tool rejected: ' + name)
                            return result['data']

                        tools = []
                        cursor = None
                        while True:
                            page = await session.list_tools(params=PaginatedRequestParams(cursor=cursor))
                            tools.extend(page.tools)
                            cursor = page.next_cursor
                            if not cursor:
                                break
                        names = {tool.name for tool in tools}
                        caps = await good('get_capabilities', {})
                        assert set(caps['supported_tools']) == names
                        assert 'https_download' in names
                        scope = caps['scoped_public_https']
                        assert scope['workspaces'] == ['cranary'] and scope['generic_shell_network'] is False
                        assert scope['methods'] == ['GET', 'HEAD']
                        assert scope['downloads']['max_response_bytes'] == 16777216
                        assert scope['downloads']['timeout_seconds'] == 60
                        deployment = await good('server_deploy_info', {})
                        assert deployment['loaded_fingerprint'] == deployment['disk_fingerprint'] == args.expected_fingerprint
                        assert not deployment['stale']
                        record['discoveries'].append({'endpoint': endpoint, 'deployment': deployment,
                            'inventory_parity': True, 'tool_names': sorted(names), 'scoped_public_https': scope})
                        save()
                        if endpoint == LOCAL:
                            continue
                        workspaces = await good('list_workspaces', {})
                        ordinary = {row['workspace_id'] for row in workspaces} - PROTECTED
                        assert len(workspaces) == 46 and len(ordinary) == 41
                        agents = await good('list_agents', {})
                        for name in ('jax', 'wei'):
                            agent = next(row for row in agents if row['agent'] == name)
                            assert set(agent['public_dispatch_workspaces']) == ordinary
                            if name == 'wei':
                                assert agent['default_model'] == 'opencode/glm-5.3-flash-free'
                        record['project_scope_preserved'] = True
                        record['wei_free_route_preserved'] = True
                        for workspace in ('cranary', 'Qman', 'm3-poc'):
                            for argv in (['python3', '-V'], ['git', 'status', '--short']):
                                result = await good('exec_run', {'workspace_id': workspace,
                                    'argv': argv, 'timeout_seconds': 20, 'network_access': False})
                                assert result['exit_code'] == 0 and not result.get('timed_out')
                                record['checks'].append({'workspace_id': workspace, 'argv': argv,
                                    'exit_code': result['exit_code'], 'stderr': result.get('stderr', '')[:2048]})
                            git = await good('git_status', {'workspace_id': workspace})
                            assert isinstance(git, str) and not git.startswith('Git error')
                        filename = 'PACKAGES-2022-06-30-receipt-check-' + secrets.token_hex(8) + '.gz'
                        payload = {'workspace_id': 'cranary', 'url': URL, 'filename': filename,
                            'expected_sha256': EXPECTED, 'max_bytes': 16777216, 'timeout_seconds': 60}
                        receipt = await good('https_download', payload)
                        assert receipt['http_status'] == 200 and receipt['sha256'] == EXPECTED
                        assert receipt['expected_sha256_verified'] is True
                        assert receipt['historical_identity_verified'] is False and receipt['training_eligible'] is False
                        assert receipt['path'] == DIRECTORY + filename
                        assert receipt['receipt_path'] == receipt['path'] + '.receipt.json'
                        assert re.fullmatch('[0-9a-f]{64}', receipt['receipt_sha256'])
                        record['acquisition'] = receipt
                        save()
                        # Reopen both saved files with O_NOFOLLOW and bounded reads
                        # in the network-disabled sandbox; verify the receipt bytes,
                        # their artifact linkage, gzip CRC and compressed checksum.
                        code = '''import gzip,hashlib,io,json,os,stat
r = RECEIPT
def bounded(path, limit):
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
 try:
  s=os.fstat(fd); assert stat.S_ISREG(s.st_mode) and s.st_size<=limit
  with os.fdopen(fd,'rb',closefd=False) as f: b=f.read(limit+1)
  assert len(b)<=limit; return b
 finally: os.close(fd)
b=bounded(r['path'],16777216); j=bounded(r['receipt_path'],65536)
assert hashlib.sha256(b).hexdigest()==r['sha256'] and len(b)==r['bytes']
assert hashlib.sha256(j).hexdigest()==r['receipt_sha256']
d=json.loads(j)
for field in ('source_url','retrieved_at','sha256','bytes','workspace_id','path','historical_identity_verified','training_eligible','expected_sha256_verified'):
 assert d[field]==r[field],field
assert not d['historical_identity_verified'] and not d['training_eligible']
f=gzip.GzipFile(fileobj=io.BytesIO(b)); expanded=f.read(67108865); f.close()
assert len(expanded)<=67108864 and expanded.count(b'Package: ')>=1000
print(json.dumps({'saved_sha256':hashlib.sha256(b).hexdigest(),'receipt_sha256':hashlib.sha256(j).hexdigest(),'receipt_integrity_verified':True,'gzip_integrity_verified':True,'package_records':expanded.count(b'Package: '),'historical_identity_verified':False}))
'''.replace('RECEIPT', repr(receipt), 1)
                        inspected = await good('exec_run', {'workspace_id': 'cranary',
                            'argv': ['python3', '-I', '-c', code], 'timeout_seconds': 30, 'network_access': False})
                        assert inspected['exit_code'] == 0
                        record['offline_saved_pair_verification'] = json.loads(inspected['stdout'])
                        for changed in ({'max_bytes': 16777217}, {'timeout_seconds': 61},
                                {'url': 'https://example.com/PACKAGES.gz'},
                                {'url': 'https://127.0.0.1/PACKAGES.gz'}, {'workspace_id': 'Qman'},
                                {'filename': '../escape.gz'},
                                {'expected_sha256': '0' * 64, 'filename': 'wrong-checksum-' + secrets.token_hex(8) + '.gz'}):
                            rejected = dict(payload, **changed)
                            result = await call('https_download', rejected)
                            assert result['is_error'], 'Expected acquisition denial'
                            record['denials'].append({'tool': 'https_download', 'changed': changed, 'denied': True})
                        post = await call('exec_run', {'workspace_id': 'cranary',
                            'argv': ['curl', '-I', '-X', 'POST', URL], 'timeout_seconds': 10, 'network_access': True})
                        assert post['is_error'] or isinstance(post['data'], dict) and post['data'].get('exit_code') == 77
                        record['denials'].append({'method': 'POST', 'denied': True})
                        save()
        public, local = (row['deployment'] for row in record['discoveries'])
        assert public['pid'] == local['pid']
        record['passed'] = True
        print(json.dumps({'passed': True, 'fingerprint': args.expected_fingerprint,
            'receipt': record['acquisition'], 'denials_passed': len(record['denials']),
            'historical_identity_verified': False}), flush=True)
    finally:
        save()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--public-key-file', type=Path, required=True)
    parser.add_argument('--expected-fingerprint', required=True)
    args = parser.parse_args()
    if not re.fullmatch('[0-9a-f]{64}', args.expected_fingerprint):
        raise ValueError('Expected immutable fingerprint required')
    os.umask(0o077)
    output = Path(tempfile.mkdtemp(prefix='a7dev-acquisition-repair-acceptance-'))
    print('Private evidence: ' + str(output), flush=True)
    key = next(line.partition('=')[2].strip().strip('\"\'')
        for line in args.public_key_file.read_text().splitlines() if line.startswith('AGENTPORTER_API_KEY='))
    asyncio.run(verify(args, key, output))


if __name__ == '__main__':
    main()
