#!/usr/bin/env python3
"""Read-only public/local MCP acceptance; --after requires the exact loaded grant.

No policy installation, sudo, restart, data-file output, or arbitrary shell
networking. Evidence is written only to a private temporary directory.
"""
import argparse
import asyncio
import datetime
import json
import os
from pathlib import Path
import re
import tempfile

from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client
from mcp.shared._httpx_utils import create_mcp_http_client

PUBLIC = 'https://1xs4h6qn-8876.use.devtunnels.ms/mcp'
LOCAL = 'http://127.0.0.1:8876/mcp'
GITHUB = 'https://api.github.com/repos/ropensci/software-review/issues/1'
HOSTS = {'api.github.com', 'cran.r-project.org', 'cran-archive.r-project.org', 'bioconductor.org'}


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


async def verify(after, key, output):
    record = {'phase': 'after' if after else 'before', 'public_endpoint': PUBLIC,
              'timestamp': datetime.datetime.now(datetime.timezone.utc).isoformat(), 'calls': []}
    def save():
        (output / 'results.json').write_text(json.dumps(record, indent=2) + '\n')
    async def call(session, endpoint, name, args):
        result = unpack(await asyncio.wait_for(session.call_tool(name, args), 35))
        record['calls'].append({'endpoint': endpoint, 'tool': name, 'arguments': args, **result})
        save()
        return result
    async def snapshot(endpoint):
        async with create_mcp_http_client(headers={'X-AgentPorter-Key': key,
                'X-Tunnel-Skip-AntiPhishing-Page': 'true'}) as client:
            client.follow_redirects = False
            async with streamable_http_client(endpoint, http_client=client) as streams:
                async with ClientSession(streams[0], streams[1]) as session:
                    await session.initialize()
                    capabilities = await call(session, endpoint, 'get_capabilities', {})
                    deployment = await call(session, endpoint, 'server_deploy_info', {})
                    assert not capabilities['is_error'] and not deployment['is_error']
                    return capabilities['data'], deployment['data']
    public_cap, public_deploy = await snapshot(PUBLIC)
    local_cap, local_deploy = await snapshot(LOCAL)
    assert public_deploy['pid'] == local_deploy['pid'], 'Public tunnel reaches another process'
    assert public_deploy['loaded_fingerprint'] == local_deploy['loaded_fingerprint']
    assert not public_deploy['stale'] and not local_deploy['stale']
    assert public_cap['scoped_public_https'] == local_cap['scoped_public_https']
    scope = public_cap['scoped_public_https']
    assert scope['generic_shell_network'] is False
    assert public_cap['sandbox']['network'] == 'disabled'
    if after:
        assert scope['enabled'] and scope['workspaces'] == ['cranary']
        assert set(scope['hosts']) == HOSTS and set(scope['methods']) == {'GET', 'HEAD'}
    else:
        assert not scope['enabled'], 'Before check expects no loaded HTTPS authorization'
    async with create_mcp_http_client(headers={'X-AgentPorter-Key': key,
            'X-Tunnel-Skip-AntiPhishing-Page': 'true'}) as client:
        client.follow_redirects = False
        async with streamable_http_client(PUBLIC, http_client=client) as streams:
            async with ClientSession(streams[0], streams[1]) as session:
                await session.initialize()
                async def execute(argv, workspace='cranary', network=True):
                    return await call(session, PUBLIC, 'exec_run', {
                        'workspace_id': workspace, 'argv': argv,
                        'timeout_seconds': 15, 'network_access': network})
                if after:
                    for url in (GITHUB, 'https://cran.r-project.org/'):
                        result = await execute(['curl', '-sSI', url])
                        assert not result['is_error'] and result['data']['exit_code'] == 0, url
                        match = re.match(r'HTTP/1\.1 ([0-9]{3})\r?\n', result['data']['stdout'])
                        assert match and match[1] == '200', 'HEAD did not return HTTP 200: ' + url
                    result = await execute(['curl', '-fsS', GITHUB])
                    assert not result['is_error'] and result['data']['exit_code'] == 0
                    issue = json.loads(result['data']['stdout'])
                    assert issue['number'] == 1 and isinstance(issue['id'], int)
                else:
                    assert (await execute(['curl', '-sSI', GITHUB]))['is_error']
                for argv, workspace in [
                    (['curl', '-sSI', 'https://example.com/'], 'cranary'),
                    (['curl', '-sSI', 'https://127.0.0.1/'], 'cranary'),
                    (['curl', '-sSI', 'https://169.254.169.254/'], 'cranary'),
                    (['curl', '-sSI', 'https://api.github.com:444/'], 'cranary'),
                    (['curl', '-sSI', 'http://api.github.com/'], 'cranary'),
                    (['curl', '-X', 'POST', GITHUB], 'cranary'),
                    (['curl', '-L', GITHUB], 'cranary'),
                    (['sh', '-c', 'curl ' + GITHUB], 'cranary'),
                    (['curl', '-sSI', GITHUB], 'agentporter-dev'),
                ]:
                    assert (await execute(argv, workspace))['is_error'], 'Unexpected network grant'
                isolation = await execute(['python3', '-I', '-c',
                    'import os,json; print(json.dumps({"cwd":os.getcwd(),'
                    '"config_visible":os.path.exists("/var/lib/agentporter-dev/config"),'
                    '"production_visible":os.path.exists("/home/yeli/repos/AgentPorter")}))'], network=False)
                assert not isolation['is_error'] and isolation['data']['exit_code'] == 0
                assert json.loads(isolation['data']['stdout']) == {
                    'cwd': '/workspace', 'config_visible': False, 'production_visible': False}
    record['passed'] = True
    record['redirect_test_scope'] = 'Live -L denied; unauthorized Location handling is covered by offline fake-response tests'
    save()
    print('PASS: ' + record['phase'] + ' public/local MCP capability, authorization and isolation checks')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--after', action='store_true', help='Run approved live GET/HEAD checks only after verifying the exact loaded grant')
    args = parser.parse_args()
    os.umask(0o077)
    output = Path(tempfile.mkdtemp(prefix='a7dev-cranary-https-verification-'))
    print('Private evidence: ' + str(output), flush=True)
    source = Path('/tmp/agentporter-development-asgard/config/secrets.env')
    key = next(line.partition('=')[2].strip().strip('\"\'') for line in source.read_text().splitlines()
               if line.startswith('AGENTPORTER_API_KEY='))
    asyncio.run(verify(args.after, key, output))


if __name__ == '__main__':
    main()
