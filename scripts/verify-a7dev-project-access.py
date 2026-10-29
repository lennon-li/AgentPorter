#!/usr/bin/env python3
"""Public MCP project access acceptance; never changes gateway configuration.

Creates and removes one exclusive temporary probe per ordinary project. Optional
--execute-jax runs two read-only provider tasks after verifying admission. No
publication, training, production calls, internal credential or generic network.
"""
import argparse
import asyncio
import datetime
import hashlib
import json
import os
from pathlib import Path
import secrets
import tempfile
import time

from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client
from mcp.shared._httpx_utils import create_mcp_http_client

PUBLIC = 'https://example-8765.use.devtunnels.ms/mcp'
LOCAL = 'http://127.0.0.1:8876/mcp'
PROTECTED = {'obsidian', 'agentporter', 'AgentPorter', 'repos', 'asgard-hermes-review'}
TRAVERSE_ONLY = {'agentporter', 'AgentPorter', 'repos'}


def summarize_workspace_access(results):
    """Classify existing ACL boundaries without changing observed read flags.

    The three protected traverse-only roots must reject directory listing.
    Every ordinary project must pass listing and the complete offline probe;
    readable protected roots still require listing and all protected execution
    must remain denied. This function performs no calls or mutations.
    """
    reasons = {}
    for name, observed in results.items():
        failed = []
        protected = name in PROTECTED
        if observed.get('protected') is not protected:
            failed.append('protection classification mismatch')
        if name in TRAVERSE_ONLY:
            if observed.get('read') is not False:
                failed.append('traverse-only listing unexpectedly allowed or unrecorded')
        elif observed.get('read') is not True:
            failed.append('required directory listing failed')
        if protected:
            if observed.get('exec_denied') is not True:
                failed.append('protected execution denial missing')
        else:
            for flag in ('offline_exec', 'read_write_remove', 'python'):
                if observed.get(flag) is not True:
                    failed.append('ordinary project ' + flag + ' failed')
            if observed.get('cwd') != '/workspace':
                failed.append('ordinary project sandbox cwd mismatch')
        if failed:
            reasons[name] = failed
    if len(results) != 46 or not PROTECTED <= set(results):
        reasons['__inventory__'] = ['Expected all 46 registered roots and five protected roots']
    ordinary = set(results) - PROTECTED
    return {
        'ordinary_projects': len(ordinary),
        'ordinary_read_write_exec_passed': len(ordinary - set(reasons)),
        'protected_traverse_only_listing_denied_expected': sorted(
            n for n in TRAVERSE_ONLY if n in results and results[n].get('read') is False),
        'protected_readable_roots_passed': sorted(
            n for n in PROTECTED - TRAVERSE_ONLY if n in results and results[n].get('read') is True),
        'failures': sorted(reasons), 'failure_reasons': reasons,
    }



def unpack(result):
    data = result.structured_content
    if data is None:
        value = ''.join(block.text for block in result.content if block.type == 'text')
        try:
            data = json.loads(value)
        except ValueError:
            data = {'message': value}
    if isinstance(data, dict) and set(data) == {'result'}:
        data = data['result']
    return {'is_error': result.is_error, 'data': data}


async def verify(args, key, output):
    record = {'passed': False, 'after': args.after,
              'timestamp': datetime.datetime.now(datetime.timezone.utc).isoformat(),
              'calls': [], 'workspaces': {}, 'provider_jobs': []}

    def save():
        (output / 'results.json').write_text(json.dumps(record, indent=2) + '\n')

    async def connect(endpoint, body):
        async with create_mcp_http_client(headers={
                'X-AgentPorter-Key': key, 'X-Tunnel-Skip-AntiPhishing-Page': 'true'}) as client:
            client.follow_redirects = False
            async with streamable_http_client(endpoint, http_client=client) as streams:
                async with ClientSession(streams[0], streams[1]) as session:
                    await session.initialize()

                    async def call(name, arguments):
                        result = unpack(await asyncio.wait_for(session.call_tool(name, arguments), 120))
                        record['calls'].append({'endpoint': endpoint, 'tool': name,
                                                'arguments': arguments, **result})
                        save()
                        return result

                    return await body(call)

    async def local(call):
        result = await call('server_deploy_info', {})
        assert not result['is_error'], result
        return result['data']

    async def public(call):
        async def good(name, arguments):
            result = await call(name, arguments)
            assert not result['is_error'], (name, arguments, result)
            return result['data']

        async def execute(workspace, argv):
            result = await good('exec_run', {'workspace_id': workspace, 'argv': argv,
                                           'network_access': False, 'timeout_seconds': 30})
            assert result['exit_code'] == 0, (workspace, result)
            return result

        deployment = await good('server_deploy_info', {})
        assert not deployment['stale']
        if args.expected_fingerprint:
            assert deployment['loaded_fingerprint'] == deployment['disk_fingerprint'] == args.expected_fingerprint
        record['deployment'] = deployment
        capabilities = await good('get_capabilities', {})
        assert capabilities['scoped_public_https']['generic_shell_network'] is False
        assert capabilities['scoped_public_https']['workspaces'] == ['cranary']
        assert set(capabilities['scoped_public_https']['methods']) == {'GET', 'HEAD'}
        inventory = await good('list_workspaces', {})
        ids = {row['workspace_id'] for row in inventory}
        assert len(ids) == 46 and PROTECTED <= ids
        ordinary = ids - PROTECTED
        for row in inventory:
            workspace = row['workspace_id']
            listing = await call('list_files', {'workspace_id': workspace, 'path': '', 'depth': 1})
            observed = {'read': not listing['is_error'],
                        'listed_entries': None if listing['is_error'] else len(listing['data']),
                        'protected': workspace in PROTECTED}
            if workspace in TRAVERSE_ONLY and listing['is_error']:
                observed['listing_denied_expected'] = True
            record['workspaces'][workspace] = observed
            if workspace in PROTECTED:
                denied = await call('exec_run', {'workspace_id': workspace, 'argv': ['true'],
                                                 'network_access': False, 'timeout_seconds': 15})
                assert denied['is_error'], ('Protected execution unexpectedly permitted', workspace)
                observed['exec_denied'] = True
            else:
                nonce = secrets.token_hex(12)
                code = ('import os,pathlib,hashlib,json; '
                        'assert os.getcwd()=="/workspace"; '
                        'p=pathlib.Path(".agentporter-access-probe-' + nonce + '"); '
                        'b=' + repr(nonce.encode()) + '; '
                        'f=p.open("xb"); f.write(b); f.close(); '
                        'assert p.read_bytes()==b; p.unlink(); '
                        'print(json.dumps({"cwd":os.getcwd(),"python":True,"read_write_remove":True}))')
                probe = await call('exec_run', {'workspace_id': workspace,
                    'argv': ['python3', '-I', '-c', code], 'network_access': False, 'timeout_seconds': 30})
                observed['offline_exec'] = not probe['is_error'] and probe['data'].get('exit_code') == 0
                if observed['offline_exec']:
                    observed.update(json.loads(probe['data']['stdout']))
                if args.after:
                    assert row['permissions']['agent_dispatch'], workspace
            save()
            print(workspace + ': ' + json.dumps(observed), flush=True)
        summary = summarize_workspace_access(record['workspaces'])
        failures = summary['failures']
        record['access_summary'] = summary
        record['access_failures'] = failures
        print('Classified access summary: ' + json.dumps(summary, sort_keys=True), flush=True)
        save()
        if args.after:
            assert not failures, failures
        if args.after:
            agents = await good('list_agents', {})
            for name in ('jax', 'wei'):
                agent = next(row for row in agents if row['agent'] == name)
                assert set(agent['public_dispatch_workspaces']) == ordinary, (name, agent)
                assert agent['delegatable'], (name, agent)
                if name == 'wei':
                    assert agent['default_model'] == 'opencode/glm-5.3-flash-free'
            record['delegation_scope_verified'] = sorted(ordinary)
            for workspace in ('Qman', 'm3-poc', 'shiny'):
                scoped = await good('list_agents', {'workspace_id': workspace})
                assert next(row for row in scoped if row['agent'] == 'jax')['delegatable']
        for workspace in ('Qman', 'm3-poc'):
            await execute(workspace, ['git', '-c', 'safe.directory=/workspace', 'status', '--short'])
        denied = [
            ('exec_run', {'workspace_id': 'Qman', 'argv': ['curl', '-fsS', 'https://api.github.com/'], 'network_access': True}),
            ('exec_run', {'workspace_id': 'cranary', 'argv': ['curl', '-X', 'POST', 'https://api.github.com/'], 'network_access': True}),
            ('exec_run', {'workspace_id': 'cranary', 'argv': ['curl', '-L', 'https://api.github.com/'], 'network_access': True}),
            ('exec_run', {'workspace_id': 'cranary', 'argv': ['curl', '-fsS', 'https://example.com/'], 'network_access': True}),
            ('read_file', {'workspace_id': 'Qman', 'path': '/var/lib/agentporter-dev/config/internal-client.key'}),
        ]
        for name, arguments in denied:
            assert (await call(name, arguments))['is_error'], (name, arguments)
        for workspace in PROTECTED:
            assert (await call('dispatch_agent', {'workspace_id': workspace, 'agent': 'jax',
                                                  'task': 'Do not launch: denial acceptance.'}))['is_error']
        code = ('import socket; s=socket.socket(); s.settimeout(2); '
                'e=s.connect_ex(("1.1.1.1",443)); s.close(); assert e!=0; print(e)')
        await execute('Qman', ['python3', '-I', '-c', code])
        record['negative_checks_passed'] = True
        if args.execute_jax:
            assert args.after
            for workspace in ('Qman', 'm3-poc'):
                marker = '.agentporter-delegation-probe-' + secrets.token_hex(12)
                challenge = secrets.token_hex(24)
                expected = hashlib.sha256(challenge.encode()).hexdigest()
                await execute(workspace, ['python3', '-I', '-c',
                    'from pathlib import Path; p=Path(' + repr(marker) + '); '
                    'f=p.open("x"); f.write(' + repr(challenge) + '); f.close()'])
                started = await good('dispatch_agent', {'agent': 'jax', 'workspace_id': workspace,
                    'read_only': True, 'purpose': 'Owner-approved project delegation acceptance',
                    'task': 'Read-only acceptance. Use your native local tool to compute the SHA256 of '
                    '/workspace/' + marker + ' and return the full digest. Do not edit, commit, push, '
                    'delegate, inspect credentials or use network acquisition tools.'})
                entry = {'workspace': workspace, 'job_id': started['job_id']}
                record['provider_jobs'].append(entry)
                save()
                deadline = time.monotonic() + 180
                while time.monotonic() < deadline:
                    result = await good('job_result', {'job_id': started['job_id'], 'max_bytes': 65536})
                    if result['status'] in {'completed', 'failed', 'cancelled', 'timed_out', 'interrupted'}:
                        break
                    await asyncio.sleep(3)
                else:
                    raise TimeoutError('Provider job still pending; preserve evidence and do not restart service')
                entry.update(status=result['status'], exit_code=result.get('exit_code'))
                await execute(workspace, ['python3', '-I', '-c',
                    'from pathlib import Path; p=Path(' + repr(marker) + '); '
                    'assert p.read_text()==' + repr(challenge) + '; p.unlink()'])
                assert result['status'] == 'completed' and result['exit_code'] == 0, entry
                assert expected in result['stdout'], entry
                entry['challenge_verified'] = True
                save()
        return deployment

    try:
        actual = await connect(PUBLIC, public)
        loopback = await connect(LOCAL, local)
        assert actual['pid'] == loopback['pid']
        assert actual['loaded_fingerprint'] == loopback['loaded_fingerprint']
        assert not loopback['stale']
        record['public_local_same_process'] = True
        record['passed'] = not record.get('access_failures')
    finally:
        save()
    return record['passed']


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--after', action='store_true')
    parser.add_argument('--execute-jax', action='store_true')
    parser.add_argument('--expected-fingerprint')
    parser.add_argument('--public-key-file', type=Path,
                        default=Path('/tmp/agentporter-development-asgard/config/secrets.env'))
    args = parser.parse_args()
    if args.execute_jax and not args.after:
        parser.error('--execute-jax requires --after')
    if args.after and not args.expected_fingerprint:
        parser.error('--after requires --expected-fingerprint')
    os.umask(0o077)
    output = Path(tempfile.mkdtemp(prefix='a7dev-project-access-verification-'))
    print('Evidence: ' + str(output), flush=True)
    key = next(line.partition('=')[2].strip().strip('\"\'')
               for line in args.public_key_file.read_text().splitlines()
               if line.startswith('AGENTPORTER_API_KEY='))
    passed = asyncio.run(verify(args, key, output))
    if not passed:
        print('Access failures recorded; inspect evidence. No gateway configuration changed.', flush=True)
        raise SystemExit(1)
    print('PASS: all 41 ordinary projects read/write/offline execution; '
          'three protected traverse-only listings remain denied; '
          'two protected readable roots listed' +
          ('; delegation scope verified' if args.after else '; baseline'), flush=True)


if __name__ == '__main__':
    main()
