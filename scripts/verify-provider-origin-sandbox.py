#!/usr/bin/env python3
"""One existing-account, synthetic-workspace origin-broker compatibility test.

Unprivileged only. Never installs, changes accounts, or mounts a real project.
The real runtime builder is exercised without its service-account admission
probe; this proves client compatibility, not installed worker UID confinement.
"""
from __future__ import annotations
import argparse
import json
import os
from pathlib import Path
import secrets
import signal
import ssl
import subprocess
import tempfile
import time

import yaml
from agentporter.agents.development import DevelopmentRuntime
from agentporter.workspaces.registry import WorkspaceRegistry
from agentporter.agents import provider_egress


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--agent', required=True, choices=['jax', 'liz', 'prof', 'ming', 'wei'])
    parser.add_argument('--execute-provider-call', action='store_true')
    parser.add_argument('--artifact-cli-root', type=Path,
                        help='Use the exact extracted candidate CLI binaries; canonical identity/model unchanged')
    args = parser.parse_args()
    if os.getuid() == 0 or not args.execute_provider_call:
        parser.error('Requires explicit unprivileged --execute-provider-call')
    os.umask(0o077)
    observations = []
    original_header = provider_egress.request_header
    vocabulary = {'backend-api', 'codex', 'v1', 'responses', 'models', 'workspaces', 'workspace',
        'routing', 'discovery', 'accounts', 'account', 'status', 'features', 'me', 'settings',
        'wham', 'usage', 'capabilities', 'permissions', 'auth', 'billing', 'plans', 'ps', 'mcp',
        'check', 'responses', 'inference', 'zen', 'go', 'openai', 'chat', 'completions', 'v2'}
    def observe_header(header, host, rules):
        # No raw URI, query, header or value is retained. Unknown path segments
        # become a constant; the vocabulary contains only static API words.
        words = header.split(b'\r\n', 1)[0].split(b' ')
        if len(words) == 3 and len(observations) < 32:
            path = words[1].split(b'?', 1)[0].decode('ascii', errors='replace')
            observations.append({'phase': 'http', 'origin': host if host in rules else '[unadmitted]',
                'method': words[0].decode() if words[0] in (b'GET', b'POST', b'DELETE') else '[other]',
                'path_shape': '/'.join(word if word in vocabulary else '[other]' for word in path.split('/') if word),
                'route_admitted': provider_egress.operation_allowed(rules, host,
                    words[0].decode('ascii', errors='replace'), path)})
        return original_header(header, host, rules)
    provider_egress.request_header = observe_header
    original_payload = provider_egress.validate_payload
    def observe_payload(header, body, host):
        try:
            return original_payload(header, body, host)
        except (PermissionError, ValueError) as error:
            safe = {'Opaque state or hosted capability is not admitted',
                'Hosted provider tool is not admitted', 'Hosted Google tool is not admitted',
                'Remote connector metadata is not admitted', 'Invalid bounded JSON request',
                'Invalid tool choice', 'Hosted tool choice is not admitted'}
            if len(observations) < 32:
                reason = error.args[0] if error.args and error.args[0] in safe else 'Payload rejected'
                observations.append({'phase': 'payload', 'reason': reason})
            raise
    provider_egress.validate_payload = observe_payload
    original_wrap = ssl.SSLContext.wrap_socket
    def observe_tls(context, *arguments, **kwargs):
        try:
            return original_wrap(context, *arguments, **kwargs)
        except ssl.SSLError as error:
            reasons = {'TLSV1_ALERT_UNKNOWN_CA', 'TLSV1_ALERT_BAD_CERTIFICATE',
                'CERTIFICATE_VERIFY_FAILED', 'SSLV3_ALERT_CERTIFICATE_UNKNOWN',
                'UNEXPECTED_EOF_WHILE_READING', 'TLSV1_ALERT_INTERNAL_ERROR'}
            if len(observations) < 32:
                observations.append({'phase': 'tls', 'reason': error.reason if error.reason in reasons else 'SSL_ERROR'})
            raise
    ssl.SSLContext.wrap_socket = observe_tls
    result = Path(tempfile.mkdtemp(prefix='provider-origin-' + args.agent + '-result-'))
    with tempfile.TemporaryDirectory(prefix='provider-origin-' + args.agent + '-') as directory:
        root = Path(directory)
        workspace = root / 'workspace'
        workspace.mkdir(mode=0o700)
        nonce = 'ORIGIN_CANARY_' + secrets.token_hex(16)
        (workspace / 'ordinary.txt').write_text(nonce + '\n')
        (root / 'config').mkdir(mode=0o700)
        config = yaml.safe_load(Path('/tmp/agentporter-development-asgard/config/development-runtime.yaml').read_text())
        config.update(network_enabled=True, egress_policy='provider_origin', parallel_search_enabled=False)
        config.pop('shared_obsidian', None)
        config.pop('shared_toolkit', None)
        spec = dict(config['workers'][args.agent])
        if args.agent == 'wei':
            # Free-default compatibility never consumes or substitutes a paid key.
            public = root / 'free-access'
            public.write_text('public\n')
            public.chmod(0o600)
            spec.update(provider='opencode', model='opencode/glm-5.3-flash-free',
                        credentials={'.config/opencode/wei-key': str(public)},
                        executable='/opt/agentporter-development/versions/20261021T132836.936455Z/cli/wei/opencode.exe')
        if args.artifact_cli_root:
            names={'jax':'codex','liz':'codex','prof':'codex','ming':'claude.exe','wei':'opencode.exe'}
            spec['executable']=str(args.artifact_cli_root.resolve()/args.agent/names[args.agent])
        executable = str(Path(spec['executable']).resolve(strict=True))
        spec['executable'] = executable
        if args.agent not in {'ming', 'wei'}:
            spec['code_mode_host'] = str(Path(executable).with_name('codex-code-mode-host'))
        config['workers'][args.agent] = spec
        # A synthetic workspace is the only registry entry. All other named
        # credential mappings are retained for the real identity-alias checks.
        registry = WorkspaceRegistry({'probe': {'path': str(workspace), 'writable': False,
            'permissions': {'agent_dispatch': True}}})
        runtime = DevelopmentRuntime(root / 'config', root / 'state', registry)
        spec = runtime._spec(args.agent, config)
        prompt = ('Bounded read-only compatibility check. Read /workspace/ordinary.txt using a native local tool, '
                  'then return its exact text. Do not edit, delegate, use network tools, inspect authentication '
                  'or configuration files, or use provider-hosted connectors. Do not invent unread content.')
        if args.agent == 'ming':
            command = [executable, '--print', prompt, '--output-format', 'stream-json', '--verbose',
                       '--permission-mode', 'dontAsk', '--allowedTools', 'Read']
        elif args.agent == 'wei':
            version = subprocess.check_output([executable,'--version'],text=True,timeout=10).strip()
            runtime._evidence['wei'] = {'cli_version':version}
            command = [executable,'run','--agent','dispatch','--format','json',prompt]
        else:
            command = [executable, 'exec', '--skip-git-repo-check', '--json',
                       '--sandbox', 'read-only', '-C', '/workspace', prompt]
        # Do not call prepare(): it deliberately requires the installed service
        # UID. This diagnostic does not pretend to be installed UID evidence.
        launch = runtime._build(args.agent, config, spec, workspace, False, command)
        started = time.monotonic()
        status, timed_out = None, False
        try:
            with (result / 'native-output.private').open('xb') as output:
                process = subprocess.Popen(launch.command, pass_fds=launch.pass_fds,
                    stdin=subprocess.DEVNULL, stdout=output, stderr=subprocess.STDOUT,
                    start_new_session=True)
                try:
                    status = process.wait(timeout=150)
                except subprocess.TimeoutExpired:
                    timed_out = True
                    os.killpg(process.pid, signal.SIGKILL)
                    status = process.wait()
        finally:
            launch.cleanup()
        output = (result / 'native-output.private').read_bytes()
        summary = {'agent': args.agent, 'returncode': status, 'timeout': timed_out,
            'duration': time.monotonic() - started, 'expected_nonce_observed': nonce.encode() in output,
            'verified': False, 'requires_native_tool_decision_review': True,
            'installed_uid_confinement_claimed': False}
        summary['observations'] = observations
        (result / 'summary.json').write_text(json.dumps(summary))
        print('NOT VERIFIED; private results: ' + str(result))


if __name__ == '__main__':
    main()
