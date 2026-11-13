#!/usr/bin/env python3
"""Prepare, never install, minimal overlays on BCC's installed v14 packages.

No configuration, credentials, model calls, service changes, or Git operations.
Every replacement must match once. Existing output is never overwritten.
"""
import argparse
import difflib
import hashlib
import json
from pathlib import Path
import shutil

REPO = Path(__file__).resolve().parents[1]
RELEASES = Path('/opt/agentporter-bcc/releases')
ALIASES = {'codex_review': 'jax', 'codex_impl': 'liz', 'codex_research': 'prof'}


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def adapt(text):
    for old, new in ALIASES.items():
        text = text.replace(old, new)
    return text


def between(text, start, end):
    return text[text.index(start):text.index(end, text.index(start))]


def prepare(output):
    output.mkdir(parents=True, exist_ok=False)
    development = (REPO/'src/agentporter/agents/development.py').read_text()
    broker_config = adapt(between(development, "        broker_config = spec.get('credential_broker')", '        canonical_credentials = {}'))
    broker_control = between(development, '            if broker_config is not None:\n                control =',
                             '        # Each identity')
    broker_stage = between(development, "            if spec.get('credential_broker') is not None and not probe:",
                           '            if agent in {')
    account = adapt(between(development, '        account = spec.get(', '        codex_config = None'))
    sharing = adapt(between(development, '                if own_auth.intersection(other_auth):',
                            '        if not isinstance(spec.get("runtime_mounts"'))
    cleanup = between(development, '            if credential_lease is not None:', '            try:\n                (root / "opaque")')
    stage = adapt(between(development, "                elif (destination == '.codex/auth.json'", '                target.chmod(0o600)'))
    transaction = (REPO/'src/agentporter/sandbox/workspace_transactions.py').read_text()
    history = between(transaction, '            history_intent = history._pull_intent', '        changes = [];new_trees=[]')
    manifests = {}
    for role in ('gateway', 'worker'):
        source = RELEASES/f'dispatch-20261107-v14-{role}/venv/lib/python3.13/site-packages/agentporter'
        destination = output/role/'agentporter'
        originals = {}
        for path in source.rglob('*'):
            if '__pycache__' in path.parts:
                continue
            if path.is_symlink():
                raise PermissionError('Installed package contains a symlink: ' + str(path))
            if path.is_file():
                originals[path.relative_to(source).as_posix()] = path.read_bytes()
        for name, raw in originals.items():
            path = destination/name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(raw)
        changed = {}

        def replace(name, old, new):
            path = destination/name
            text = path.read_text()
            if text.count(old) != 1:
                raise ValueError(f'{role}/{name}: expected exactly one matching patch anchor')
            path.write_text(text.replace(old, new, 1))

        lease = (REPO/'src/agentporter/agents/credential_lease.py').read_bytes()
        (destination/'agents/credential_lease.py').write_bytes(lease)
        (destination/'agents/credential_broker.py').write_bytes((REPO/'src/agentporter/agents/credential_broker.py').read_bytes())
        (destination/'agents/native_codex_auth.py').write_bytes((REPO/'src/agentporter/agents/native_codex_auth.py').read_bytes())
        replace('agents/development.py', '        canonical_credentials = {}\n', broker_config+'        canonical_credentials = {}\n')
        replace('agents/development.py', '        # Each identity has an independently provisioned authentication file.\n',
                broker_control+'        # Each identity has an independently provisioned authentication file.\n')
        replace('agents/development.py', '        if not own_auth:\n', '        if not own_auth and broker_config is None:\n')
        replace('agents/development.py', '        headroom_proxy = None\n',
                '        headroom_proxy = None\n        credential_lease = None\n')
        replace('agents/development.py', '            for descriptor in descriptors:\n                os.close(descriptor)\n',
                '            for descriptor in descriptors:\n                os.close(descriptor)\n' + cleanup)
        replace('agents/development.py', '                else:\n                    shutil.copyfile(source, target)\n', stage)
        replace('agents/development.py', '                    shutil.copyfile(source, target)\n                target.chmod(0o600)\n',
                '                    shutil.copyfile(source, target)\n                target.chmod(0o600)\n'+broker_stage)
        replace('agents/development.py', '        codex_config = None\n', account+'        codex_config = None\n')
        replace('agents/development.py', '                if own_auth.intersection(other_auth):\n                    raise PermissionError(f"development worker credentials are shared: {agent}/{name}")\n', sharing)
        replace('agents/policy.py', 'return cls(git_commit=True, git_push=False)', 'return cls(git_commit=False, git_push=False)')
        replace('agents/policy.py', '"""Writable workspace membership permits commits; agents never push."""',
                '"""Worker flags cannot grant independent commit or push approval."""')
        replace('agents/policy.py', '            f"- git commit: {\'allowed inside writable workspace\' if self.git_commit else \'NOT allowed (read-only)\'}\\n"',
                '            "- git commit: requires separate server-verified owner approval; do not commit in this job\\n"')
        replace('agents/broker.py', '        if allow_push:\n            raise PermissionError("Delegated Git push is disabled")\n',
                '        if allow_push:\n            raise PermissionError("Delegated Git push is disabled")\n        if allow_commit:\n            raise PermissionError("Worker commit flags are not independent owner approval")\n')
        replace('agents/broker.py',
                "'After success continue scoped edits/tests/commits; canonical publication occurs at successful '",
                "'After success continue scoped edits and tests. Workspace file changes persist after successful '")
        replace('agents/broker.py',
                "'job cleanup. If refused, report the exact refusal without changing scope. '",
                "'job cleanup. Commits require owner-run Git separately. If refused, report the exact refusal without changing scope. '")
        replace('agents/production_relay.py', '    if data.get("allow_push"):\n        raise PermissionError("Relay never permits Git push")\n',
                '    if data.get("allow_push"):\n        raise PermissionError("Relay never permits Git push")\n    if data.get("allow_commit"):\n        raise PermissionError("Relay commit flags are not independent owner approval")\n')
        replace('agents/production_relay.py', '"allow_commit": not read_only,', '"allow_commit": False,')
        old = between((source/'action_policy.py').read_text(), '            if read_only is False and self.effective_mode("git_commit",', '        if mode == "LOCKED"')
        replace('action_policy.py', old, "            if arguments.get('allow_commit') or arguments.get('allow_push'):\n                raise PermissionError('Worker commit/push flags cannot grant independent owner approval')\n")
        replace('action_policy.py', '    "git_commit",\n', '')
        replace('action_policy.py', 'APPROVAL_ACTIONS = frozenset({\n', 'APPROVAL_ACTIONS = frozenset({\n    "git_commit",\n')
        replace('sandbox/repository_birth.py', '            manifest=_manifest(path,budget=metadata_budget,deadline=deadline,clone=clone)\n',
                "            if clone is None:\n                raise UnsafeWorkspaceDelta('Repository creation requires independent owner approval')\n            manifest=_manifest(path,budget=metadata_budget,deadline=deadline,clone=clone)\n")
        replace('sandbox/workspace_transactions.py', '        for history in self.git_histories.values():\n            history.prepare()\n',
                '        for history in self.git_histories.values():\n            history.prepare()\n' + history)
        replace('git_pulls.py', "            if observed['unmerged'] or observed['object_format'] != expected['object_format']:\n                raise PermissionError('Worker pull final candidate is unresolved or has another object format')\n",
                "            if observed['unmerged'] or observed['object_format'] != expected['object_format']:\n                raise PermissionError('Worker pull final candidate is unresolved or has another object format')\n            if any(observed[field] != expected[field] for field in ('head', 'branch')):\n                raise PermissionError('Approved inbound Git does not authorize a subsequent worker commit or checkout')\n")
        replace('server.py', '    from agentporter.git_commits import WorkspaceGitCommits\n    approved_commits = (WorkspaceGitCommits(registry, sandbox, job_manager=job_manager)',
                '    from agentporter.git_policy import load_approved_commits\n    approved_commits = (load_approved_commits(config.config_dir, registry, sandbox, job_manager)')
        for old, new in [
            ('Workspaces admitted for local edits and commits by public policy, registry, and development runtime; push remains denied.', 'Workspaces admitted for local edits by public policy, registry, and development runtime. Commit and push require separate authority.'),
            ('Legacy field; omit for workspace commits.', 'Exact owner receipt when a signed commit backend is enabled; cannot unlock a LOCKED action.'),
            ('Legacy field; workspace commits execute directly.', 'Prepare an exact proposal only when the operator enables a signed commit backend.'),
            ('Compatibility flag; writable workers can commit without confirmation.', 'Must be false. Worker flags cannot grant independent owner commit approval.'),
        ]:
            # Two obsolete receipt fields share the same old text.
            path = destination/'rest/schemas.py'
            text = path.read_text()
            if text.count(old) not in (1, 2):
                raise ValueError('REST approval schema anchor changed')
            path.write_text(text.replace(old, new))
        replace('server.py', 'Commit explicitly staged workspace changes without a phone receipt.',
                'Commit only when an independently approved backend and operator policy permit it.')
        replace('server.py', 'restricted by protected dispatch/commit policy', 'restricted by protected dispatch policy')
        replace('server.py', "approved_git_commits=config.sandbox.workspace_transactions and context['job_manager'].resources is not None,", 'approved_git_commits=False,')
        if role == 'gateway':
            replace('qman_live.py', "reason in {'live_quota_capability_not_installed','live_quota_capability_not_authorized'}",
                    "reason in {'live_quota_capability_not_installed','live_quota_capability_not_authorized','live_quota_requires_exact_provider_profile'}")
            replace('qman_live.py', '        _select(provider,profile,model); p = policy(config_dir)',
                "        try:\n            _select(provider,profile,model)\n        except (ValueError, TypeError):\n            return _unavailable('live_quota_requires_exact_provider_profile',provider,profile,started)\n        p = policy(config_dir)")
        # REST previously ignored an explicit cache-mode query. Keep the MCP
        # and REST arguments aligned; a caller can now demand no fallback.
            replace('server.py', '                     model: Optional[str] = None):\n        """Read Qman quota evidence without credential refresh or dispatch."""',
                '                     model: Optional[str] = None, allow_cached_fallback: bool = False):\n        """Read Qman evidence with explicit cache policy; no model dispatch."""')
            replace('server.py', '                                                    profile=profile, live=live, model=model)',
                '                                                    profile=profile, live=live, model=model,\n                                                    allow_cached_fallback=allow_cached_fallback)')
        patches = []
        for path in sorted(destination.rglob('*')):
            if not path.is_file():
                continue
            name = path.relative_to(destination).as_posix()
            raw = path.read_bytes()
            old = originals.get(name)
            if raw != old:
                changed[name] = {'before_sha256': digest(old) if old is not None else None,
                                 'after_sha256': digest(raw)}
                patches.extend(difflib.unified_diff((old or b'').decode().splitlines(True), raw.decode().splitlines(True),
                                                   fromfile='a/'+name, tofile='b/'+name))
        (output/(role+'.patch')).write_text(''.join(patches))
        manifests[role] = {'source': str(source), 'original_files': {name: digest(raw) for name, raw in sorted(originals.items())},
                           'changed_files': changed}
    helper = Path('/usr/local/libexec/agentporter-bcc-refresh-credentials.py')
    helper_raw = helper.read_bytes()
    original_shebang, separator, body = helper_raw.partition(b'\n')
    if original_shebang != b'#!/usr/bin/python3' or not separator:
        raise ValueError('Credential helper interpreter changed; inspect before preparing')
    python = RELEASES/'dispatch-20261107-v14-worker/venv/bin/python'
    repaired = ('#!'+str(python)+'\n').encode()+body
    operator = output/'operator'
    operator.mkdir()
    (operator/helper.name).write_bytes(repaired)
    owner_uid = 2056259175
    socket_path = '/run/agentporter-bcc-auth/auth.sock'
    native_executable = '/opt/agentporter-bcc/shared-cli/codex-0.167.2/bin/codex'
    policy = {'version': 1, 'mode': 'access_only', 'owner_uid': owner_uid, 'worker_uid': 997,
        'socket_path': socket_path, 'state_dir': '/home/yeli/.local/state/agentporter-bcc-auth',
        'forbidden_roots': ['/home/yeli/repos'],
        'accounts': {name: {'auth_file': '/home/yeli/'+home+'/auth.json',
                           'native_socket': '/home/yeli/'+home+'/app-server-control/app-server-control.sock',
                           'account_id': '@NATIVE_ACCOUNT_BINDING_REQUIRED@'}
                     for name, home in [('jax', '.codex'), ('liz', '.codex-liz'), ('prof', '.codex-prof')]}}
    (operator/'credential-broker.json').write_text(json.dumps(policy, indent=2))
    delta = {name: {'remove_credential': '.codex/auth.json', 'credential_broker': {
        'owner_uid': owner_uid, 'socket_path': socket_path, 'account': name},
        'executable': native_executable,
        'code_mode_host': str(Path(native_executable).with_name('codex-code-mode-host'))}
        for name in policy['accounts']}
    (operator/'worker-config-delta.json').write_text(json.dumps(delta, indent=2))
    (operator/'action-policy-delta.json').write_text(json.dumps({
        'version': 1, 'action_modes': {'git_commit': 'LOCKED', 'git_push': 'LOCKED'}}, indent=2))
    # RELEASE_PYTHON is deliberately unresolved. The operator seals it to the
    # verified new release; a template cannot be mistaken for an installed unit.
    (operator/'agentporter-bcc-credential-broker.service.in').write_text('''[Unit]
Description=BCC native account credential custody
After=local-fs.target

[Service]
Type=simple
User=yeli
Group=agentporter-bcc-worker
UMask=0077
RuntimeDirectory=agentporter-bcc-auth
RuntimeDirectoryMode=0710
ExecStart=@RELEASE_PYTHON@ -I -B -m agentporter.agents.credential_broker --policy /etc/agentporter-bcc/credential-broker.json serve
Restart=on-failure
NoNewPrivileges=yes
PrivateNetwork=yes
PrivateTmp=no
ProtectSystem=strict
ReadWritePaths=/home/yeli/.local/state/agentporter-bcc-auth
RestrictAddressFamilies=AF_UNIX

[Install]
WantedBy=multi-user.target
''')
    (output/'MANIFEST.json').write_text(json.dumps({'version': 1, 'deployment_performed': False,
        'roles': manifests, 'operator_helper': {'path': str(helper), 'before_sha256': digest(helper_raw),
        'after_sha256': digest(repaired), 'interpreter': str(python)},
        'operator_files': {p.name: digest(p.read_bytes()) for p in sorted(operator.iterdir())},
        'activation_allowed': False,
        'git_workflow': 'owner-run Git after explicit chat approval; B6 commit and push LOCKED',
        'activation_gates': ['native account binding enrollment', 'native daemon renewal protocol verification',
            'sealed production control rebind', 'live acceptance and rollback trial']}, indent=2))
    print(json.dumps({'output': str(output), 'changed_files': {role: len(row['changed_files']) for role, row in manifests.items()}}))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True, type=Path)
    prepare(parser.parse_args().output.resolve())
