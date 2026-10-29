#!/usr/bin/env python3
"""Inspect public/local MCP discovery and acquire one approved test snapshot.

No gateway changes. New bytes are published only by the gateway's constrained
https_download into its approved acquisition directory; no dataset is promoted.
"""
import asyncio
import datetime
import json
import os
from pathlib import Path
import secrets
import tempfile

from mcp import ClientSession
from mcp.types import PaginatedRequestParams
from mcp.client.streamable_http import streamable_http_client
from mcp.shared._httpx_utils import create_mcp_http_client

PUBLIC = 'https://gateway.example.invalid/mcp'
LOCAL = 'http://127.0.0.1:8876/mcp'
URL = 'https://packagemanager.posit.co/cran/2022-06-30/src/contrib/PACKAGES.gz'
DIRECTORY = 'data-raw/cran-history/reports/2026-10-21-authorized-acquisition/downloads/'


def unpack(result):
    data = result.structured_content
    if data is None:
        text = ''.join(item.text for item in result.content if item.type == 'text')
        try:
            data = json.loads(text)
        except ValueError:
            data = {'message': text}
    if isinstance(data, dict) and set(data) == {'result'}:
        data = data['result']
    return {'is_error': result.is_error, 'data': data}


async def main():
    os.umask(0o077)
    output = Path(tempfile.mkdtemp(prefix='a7dev-binary-discovery-'))
    print('Evidence: ' + str(output), flush=True)
    key = next(line.partition('=')[2].strip().strip('\"\'')
               for line in Path('/tmp/agentporter-development-asgard/config/secrets.env').read_text().splitlines()
               if line.startswith('AGENTPORTER_API_KEY='))
    record = {'passed': False, 'timestamp': datetime.datetime.now(datetime.timezone.utc).isoformat(),
              'calls': [], 'discoveries': [], 'chatgpt_registration_refreshed': False,
              'chatgpt_native_invocation_verified': False}

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
                        tools = []
                        cursor = None
                        while True:
                            result = await session.list_tools(params=PaginatedRequestParams(cursor=cursor))
                            tools.extend(result.tools)
                            cursor = result.next_cursor
                            if not cursor:
                                break
                        download = next(tool for tool in tools if tool.name == 'https_download')
                        descriptor = download.model_dump(by_alias=True, exclude_none=True)
                        schema = descriptor['inputSchema']
                        assert set(schema['required']) == {'workspace_id', 'url', 'filename'}
                        assert {'workspace_id', 'url', 'filename', 'expected_sha256', 'max_bytes', 'timeout_seconds'} <= set(schema['properties'])
                        assert schema['properties']['max_bytes']['default'] == 16777216
                        assert schema['properties']['timeout_seconds']['default'] == 60
                        record['discoveries'].append({'endpoint': endpoint, 'tool_names': [tool.name for tool in tools],
                                                       'https_download': descriptor})
                        save()

                        async def call(name, arguments):
                            result = unpack(await asyncio.wait_for(session.call_tool(name, arguments), 90))
                            record['calls'].append({'endpoint': endpoint, 'tool': name, 'arguments': arguments, **result})
                            save()
                            return result

                        async def good(name, arguments):
                            result = await call(name, arguments)
                            assert not result['is_error'], (name, result)
                            return result['data']

                        deployment = await good('server_deploy_info', {})
                        assert not deployment['stale']
                        record['discoveries'][-1]['deployment'] = deployment
                        if endpoint == LOCAL:
                            continue
                        capability = await good('get_capabilities', {})
                        assert capability['scoped_public_https']['generic_shell_network'] is False
                        assert capability['scoped_public_https']['workspaces'] == ['cranary']
                        filename = 'PACKAGES-2022-06-30-tool-discovery-' + secrets.token_hex(8) + '.gz'
                        payload = {'workspace_id': 'cranary', 'url': URL, 'filename': filename,
                                   'max_bytes': 16777216, 'timeout_seconds': 60}
                        receipt = await good('https_download', payload)
                        assert receipt['http_status'] == 200 and 0 < receipt['bytes'] <= 16777216
                        assert receipt['path'] == DIRECTORY + filename
                        record['receipt'] = receipt
                        code = ('import gzip,hashlib,io,json; from pathlib import Path; '
                                'p=Path(' + repr(receipt['path']) + '); '
                                'assert p.stat().st_size==' + str(receipt['bytes']) + '; '
                                'raw=p.read_bytes(); digest=hashlib.sha256(raw).hexdigest(); '
                                'assert digest==' + repr(receipt['sha256']) + '; '
                                'f=gzip.GzipFile(fileobj=io.BytesIO(raw)); expanded=f.read(67108865); f.close(); '
                                'assert len(expanded)<=67108864; '
                                'records=expanded.count(b"Package: "); assert records>=1000; '
                                'print(json.dumps({"saved_sha256":digest,"saved_bytes":len(raw),'
                                '"gzip_integrity_verified":True,"expanded_sha256":hashlib.sha256(expanded).hexdigest(),'
                                '"expanded_bytes":len(expanded),"package_records":records}))')
                        verified = await good('exec_run', {'workspace_id': 'cranary',
                            'argv': ['python3', '-I', '-c', code], 'network_access': False, 'timeout_seconds': 30})
                        assert verified['exit_code'] == 0, verified
                        record['offline_verification'] = json.loads(verified['stdout'])
                        # These must all be denied before a byte can be published.
                        denials = [dict(payload, max_bytes=16777217), dict(payload, timeout_seconds=61),
                                   dict(payload, url='https://example.com/PACKAGES.gz'),
                                   dict(payload, url='https://127.0.0.1/PACKAGES.gz'),
                                   dict(payload, workspace_id='Qman'),
                                   dict(payload, filename='../escape.gz'),
                                   dict(payload, filename='checksum-denial-' + secrets.token_hex(8) + '.gz', expected_sha256='0' * 64)]
                        for rejected in denials:
                            assert (await call('https_download', rejected))['is_error'], rejected
                        record['download_denials_passed'] = len(denials)
        public, local = (entry['deployment'] for entry in record['discoveries'])
        assert public['pid'] == local['pid']
        assert public['loaded_fingerprint'] == local['loaded_fingerprint']
        assert record['discoveries'][0]['https_download'] == record['discoveries'][1]['https_download']
        record['passed'] = True
        print(json.dumps({key: record[key] for key in ('receipt', 'offline_verification', 'download_denials_passed')}), flush=True)
        print('PASS: server discovery and public MCP invocation; ChatGPT account refresh remains separate.', flush=True)
    finally:
        save()


if __name__ == '__main__':
    asyncio.run(main())
