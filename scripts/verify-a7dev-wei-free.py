#!/usr/bin/env python3
"""Inspect Wei's public MCP route; optional one read-only free-model acceptance.

--execute-free-check refuses any paid/default mismatch before dispatch. It
never dispatches Phil, changes configuration, restarts services or edits files.
"""
import argparse
import asyncio
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import tempfile
import time

from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client
from mcp.shared._httpx_utils import create_mcp_http_client

PUBLIC = 'https://1xs4h6qn-8876.use.devtunnels.ms/mcp'
MODEL = 'opencode/glm-5.3-flash-free'


async def verify(execute, key, output):
    record = {'timestamp': datetime.datetime.now(datetime.timezone.utc).isoformat(),
              'endpoint': PUBLIC, 'calls': [], 'provider_call_requested': execute}
    def save():
        (output / 'results.json').write_text(json.dumps(record, indent=2) + '\n')
    async with create_mcp_http_client(headers={'X-AgentPorter-Key': key,
            'X-Tunnel-Skip-AntiPhishing-Page': 'true'}) as client:
        client.follow_redirects = False
        async with streamable_http_client(PUBLIC, http_client=client) as streams:
            async with ClientSession(streams[0], streams[1]) as session:
                await session.initialize()
                async def call(name, args):
                    result = await asyncio.wait_for(session.call_tool(name, args), 90)
                    data = result.structured_content
                    if data is None:
                        text = ''.join(item.text for item in result.content if item.type == 'text')
                        try: data = json.loads(text)
                        except ValueError: data = {'message': text}
                    if isinstance(data, dict) and set(data) == {'result'}:
                        data = data['result']
                    record['calls'].append({'tool': name, 'arguments': args,
                                            'is_error': result.is_error, 'data': data})
                    save()
                    assert not result.is_error, name + ': tool returned an error; inspect private evidence'
                    return data
                deployed = await call('server_deploy_info', {})
                assert not deployed['stale']
                agents = await call('list_agents', {})
                wei = next(row for row in agents if row['agent'] == 'wei')
                print(json.dumps({k: wei.get(k) for k in
                    ['agent', 'provider', 'configured_model', 'default_model', 'delegatable', 'cli_version']}), flush=True)
                if not execute:
                    print('Inspect only: no model calls, configuration changes or restarts.')
                    return
                assert wei['provider'] == 'opencode' and wei['configured_model'] == MODEL
                assert wei['default_model'] == MODEL and wei['delegatable']
                readme = Path('/home/yeli/agent-work/agentporter-dev/README.md')
                expected = hashlib.sha256(readme.read_bytes()).hexdigest()
                task = ('Read-only Wei free-default acceptance. Use a native local tool to compute '
                        'the SHA256 of /workspace/README.md and return the full hexadecimal digest. '
                        'Do not edit files, use internet tools, delegate, inspect credentials or configuration, '
                        'commit or push. Do not guess the digest.')
                started = await call('dispatch_agent', {'agent': 'wei', 'workspace_id': 'agentporter-dev',
                    'task': task, 'purpose': 'Verify owner-approved Wei free default repair', 'read_only': True})
                job_id = started['job_id']
                deadline = time.monotonic() + 150
                while time.monotonic() < deadline:
                    result = await call('job_result', {'job_id': job_id, 'max_bytes': 65536})
                    if result['status'] in {'completed', 'failed', 'cancelled', 'timeout', 'timed_out'}:
                        break
                    await asyncio.sleep(3)
                else:
                    raise TimeoutError('Job did not finish within acceptance deadline; job ID is retained in private evidence')
                assert result['status'] == 'completed' and result['exit_code'] == 0
                assert result['provider'] == 'opencode' and result['configured_model'] == MODEL
                assert re.search(r'(?<![0-9a-f])' + expected + r'(?![0-9a-f])', result['stdout'])
                assert hashlib.sha256(readme.read_bytes()).hexdigest() == expected
                record['passed'] = True
                record['verified_scope'] = 'Public MCP default Wei free-route read-only task; no native tool trace claim'
                save()
                print('PASS: public Wei default free-model task; matching README SHA256; job ' + job_id)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--execute-free-check', action='store_true')
    args = parser.parse_args()
    os.umask(0o077)
    output = Path(tempfile.mkdtemp(prefix='a7dev-wei-free-public-'))
    print('Private evidence: ' + str(output), flush=True)
    source = Path('/tmp/agentporter-development-asgard/config/secrets.env')
    key = next(line.partition('=')[2].strip().strip('\"\'') for line in source.read_text().splitlines()
               if line.startswith('AGENTPORTER_API_KEY='))
    asyncio.run(verify(args.execute_free_check, key, output))


if __name__ == '__main__':
    main()
