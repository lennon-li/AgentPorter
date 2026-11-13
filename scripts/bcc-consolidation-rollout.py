#!/usr/bin/env python3
"""BCC consolidation: read-only plan, sealed staging, guarded activation/rollback.

Run a hash-bound copy with installed isolated Python. Never imports workspace
code as root. Existing root-owned controls supply admission and discovery locks.
Native auth is read only for exact account enrollment, never copied or logged.
"""
import argparse
import base64
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import secrets
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

import yaml

OWNER, GROUP, WORKER = 2056259175, 2056259276, 997
BASE = Path('/home/yeli/repos/AgentPorter/artifacts/bcc-consolidation-20261112')
CANDIDATE = BASE/'candidate-v16'
CANDIDATE_SHA = '02a8c747784669c1ac1549a670ec49b9d942ccd272ee2895f871a65048321f12'
CONTROL = Path('/var/lib/agentporter-bcc/consolidation-20261113-04')
HELPER = Path('/usr/local/libexec/agentporter-bcc-nida-app-update-13.py')
HELPER_SHA = '36060c762009712edbf1ab1cd7685b07948c22a000f6e7dc1b4091db63a1b002'
SITE = Path('venv/lib/python3.13/site-packages/agentporter')
OLD = {r: Path('/opt/agentporter-bcc/releases/dispatch-20261107-v14-'+r) for r in ('gateway','worker')}
NEW = {r: Path('/opt/agentporter-bcc/releases/consolidation-20261113-04-'+r) for r in OLD}
# updateCLI-ubuntu.sh updated these root-owned CLI copies after staging.
# Pin that observed maintenance exactly; every other baseline byte and mode
# still has to match the original sealed release. New releases omit this unused
# embedded tree and use the explicit external executable paths in worker policy.
LEGACY_CLI_MAINTENANCE = {
    'cli/codex/codex': 'a8cb58c528c76e7313d4a70294ec614757b0f4c7bf9683e11c88ecad8c3d421b',
    'cli/codex/codex-code-mode-host': 'e1a56831a087bfeb1a91d43b7265fd1c38b898396b09ab357dc751d641ad25bd',
    'cli/ming/claude': '604d29a6869409106b6a1110bdadcc8b72e8654a5a865d23258f938a696e348e',
    'cli/phil/copilot': '52496feac05f5ca6d53a16590adfcd2f74de2b5188542840cba447bc2bb19e18',
    'cli/argie/agy': '9db59b6371107b939befa9c507c0a24989fda974e75d81d8529f3689ef7322e5',
    'cli/wei/opencode': '8d6e8464a306e14429bad028cb06d05cd8aacd75c1bc811b3b816dc64d509122',
}
CONFIG = {'gateway': Path('/home/yeli/.config/agentporter'),
    'worker': Path('/var/lib/agentporter-bcc-worker/staging/bcc-stage-20261027-03/config')}
AUTH_POLICY = Path('/etc/agentporter-bcc/credential-broker.json')
AUTH_UNIT = Path('/etc/systemd/system/agentporter-bcc-credential-broker.service')
AUTH_STATE = Path('/home/yeli/.local/state/agentporter-bcc-auth')
AUTH_SOCKET = Path('/run/agentporter-bcc-auth/auth.sock')
CLI = Path('/opt/agentporter-bcc/shared-cli/codex-0.167.2/bin/codex')
STATE = CONTROL/'status.json'


def require(value, message):
    if not value:
        raise PermissionError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def read(path, limit=4*1024**2):
    fd = os.open(path, os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
    try:
        info = os.fstat(fd)
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and not info.st_mode & 0o022
                and info.st_size <= limit, 'Unsafe rollout input')
        raw = os.pread(fd, limit+1, 0)
        require(len(raw) == info.st_size and os.fstat(fd) == os.stat(path, follow_symlinks=False) == info,
                'Rollout input changed while reading')
        return raw
    finally:
        os.close(fd)


def atomic(path, raw, uid=0, gid=0, mode=0o600):
    fd, temporary = tempfile.mkstemp(prefix='.bcc-consolidation-', dir=path.parent)
    try:
        os.fchmod(fd, mode)
        os.fchown(fd, uid, gid)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def controls():
    for path in (*reversed(HELPER.parents), HELPER):
        info = path.lstat()
        require(info.st_uid == 0 and not info.st_mode & 0o022 and not path.is_symlink(), 'Untrusted installed controls')
    raw = read(HELPER)
    require(sha(raw) == HELPER_SHA, 'Installed admission controls changed')
    spec = importlib.util.spec_from_file_location('bcc_installed_controls', HELPER)
    helper = importlib.util.module_from_spec(spec)
    exec(compile(raw, str(HELPER), 'exec'), helper.__dict__)
    # Rebind only current, independently inspected root controls. Do not replay
    # a historical updater's old release, catalog or discovery fingerprints.
    helper.PLAN['common_manifest'] = {'identity': helper.identity(helper.COMMON), 'raw_hex': read(helper.COMMON).hex()}
    helper.PLAN['state_identities'] = {r: helper.identity(Path(v['state'])) for r,v in helper.ROLES.items()}
    helper.PLAN['discovery_controls'] = {p: {'identity': helper.identity(Path(p)), 'sha256': sha(read(p))}
        for p in helper.PLAN['discovery_controls']}
    helper.CONTROL = CONTROL/'events'
    return helper


def catalog_correction(helper):
    before = read(helper.COMMON)
    value = json.loads(before)
    canonical = lambda v: json.dumps(v, sort_keys=True, separators=(',', ':')).encode()
    require(value['manifest_sha256'] == sha(canonical({k:v for k,v in value.items() if k != 'manifest_sha256'})),
            'Existing catalog digest differs')
    changed = []
    for domain in value['domains']:
        for row in domain['projects']:
            path = Path(row['canonical'])
            native = helper.identity(path)[:5]
            mapped = helper.identity(Path(domain['view_root'])/path.name)[:5]
            require(native[:4] == row['identity'][:4] and mapped == native[:2]+[997,997,native[4]],
                    'Catalog inode, owner or mapping drift requires separate reconciliation')
            if native != row['identity']:
                require(path == Path('/home/yeli/repos/cranary') and row['identity'][4] == 0o775
                        and native[4] == 0o770, 'Unreviewed catalog permissions drift')
                changed.append({'project': path.name, 'before_mode': '0775', 'after_mode': '0770'})
                row['identity'] = native
    value['manifest_sha256'] = sha(canonical({k:v for k,v in value.items() if k != 'manifest_sha256'}))
    return before, canonical(value)+b'\n' if changed else before, changed


def baseline(helper):
    result = {'units': {}, 'configs': {}, 'releases': {}, 'databases': {}}
    for role in OLD:
        root = OLD[role]
        manifest = read(root/'RELEASE.json')
        expected = copy.deepcopy(json.loads(manifest)['files'])
        require(set(LEGACY_CLI_MAINTENANCE) <= set(expected), 'Legacy CLI file set changed')
        for name, digest in LEGACY_CLI_MAINTENANCE.items():
            expected[name] = {'sha256': digest}
        require(expected == helper.files_manifest(root, sealed=False), 'Unreviewed installed release drift')
        for path in (root, *root.rglob('*')):
            relative = path.relative_to(root).as_posix()
            if path.is_symlink():
                continue
            info = path.lstat()
            allowed_mode = 0o755 if relative in LEGACY_CLI_MAINTENANCE else None
            require(info.st_uid == 0 and (stat.S_IMODE(info.st_mode) == allowed_mode
                if allowed_mode is not None else not info.st_mode & 0o222), 'Unreviewed installed release permissions')
        result['releases'][role] = {'manifest_sha256': sha(manifest), 'fingerprint': helper.fingerprint(root/SITE)}
        result['units'][role] = {'sha256': sha(read(helper.unit_path(role))), 'identity': helper.identity(helper.unit_path(role))}
        for name in helper.PROFILE_FILES[role]:
            path = CONFIG[role]/name
            if path.exists():
                result['configs'][str(path)] = {'sha256': sha(read(path)), 'identity': helper.identity(path)}
        result['databases'][role] = json.loads(helper.guard(role, 'probe', '0'*32))['database_identity']
    raw, _, corrections = catalog_correction(helper)
    result['catalog'] = {'sha256': sha(raw), 'identity': helper.identity(helper.COMMON), 'corrections': corrections}
    result['discovery_controls'] = helper.PLAN['discovery_controls']
    result['common_source'] = json.loads(raw)['domains'][0]['source_identity']
    result['legacy_cli_maintenance'] = LEGACY_CLI_MAINTENANCE
    require(not AUTH_UNIT.exists() and not AUTH_POLICY.exists(), 'Existing broker controls need explicit reconciliation')
    return result


def save(state, phase):
    state['phase'] = phase
    atomic(STATE, json.dumps(state, indent=2, sort_keys=True).encode())
    print(json.dumps({'phase': phase}), flush=True)


def system(*args):
    result = subprocess.run(['/usr/bin/systemctl', *args], capture_output=True, timeout=60)
    require(result.returncode == 0, 'Service operation failed: '+args[0])
    return result.stdout.decode().strip()


def api(helper, role, path):
    raw = read(CONFIG[role]/'secrets.env')
    keys = [line.split(b'=',1)[1].strip() for line in raw.splitlines() if line.startswith(b'AGENTPORTER_API_KEY=')]
    require(len(keys) == 1 and keys[0], 'Existing API key unavailable')
    request = urllib.request.Request('http://127.0.0.1:'+str(helper.ROLES[role]['port'])+path,
        headers={'X-AgentPorter-Key': keys[0].decode()})
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(request, timeout=3) as response:
        return json.loads(response.read(2*1024**2))


def live(helper, role, root, fingerprint):
    deadline = time.monotonic()+35
    while time.monotonic() < deadline:
        try:
            value = api(helper, role, '/api/v1/server/deploy-info')
            pid = int(system('show', helper.ROLES[role]['unit'], '-p', 'MainPID', '--value'))
            require(value['pid'] == pid and pid > 0 and value['package_path'] == str(root/SITE)
                and value['loaded_fingerprint'] == value['disk_fingerprint'] == fingerprint
                and value['stale'] is False, 'Live source/PID proof differs')
            return pid
        except (OSError, ValueError, KeyError):
            time.sleep(.5)
    raise PermissionError('Live source/PID proof unavailable')


def stage(helper, state):
    manifest_raw = read(CANDIDATE/'MANIFEST.json')
    require(sha(manifest_raw) == CANDIDATE_SHA, 'Reviewed candidate manifest changed')
    manifest = json.loads(manifest_raw)
    require(not STATE.exists(), 'Existing rollout retained; inspect it instead of restaging')
    CONTROL.mkdir(mode=0o755)
    (CONTROL/'events').mkdir(mode=0o700)
    (CONTROL/'payload').mkdir(mode=0o755)
    state.update(baseline=baseline(helper), candidate_manifest_sha256=sha(manifest_raw), files={}, guarded=[], nonce=secrets.token_hex(16))
    atomic(CONTROL/'candidate-manifest.json', manifest_raw, mode=0o444)
    save(state, 'baseline_captured')
    for role in OLD:
        package = OLD[role]/SITE
        original = manifest['roles'][role]['original_files']
        actual = {p.relative_to(package).as_posix(): sha(read(p)) for p in package.rglob('*')
            if p.is_file() and '__pycache__' not in p.parts}
        require(actual == original, 'Candidate installed base changed')
        require(not NEW[role].exists(), 'New release already exists; preserve it')
        shutil.copytree(OLD[role], NEW[role], symlinks=True,
            ignore=lambda directory, names: ['cli'] if Path(directory) == OLD[role] and 'cli' in names else [])
        for directory, _, _ in os.walk(NEW[role]):
            Path(directory).chmod(0o755)
        for name, row in manifest['roles'][role]['changed_files'].items():
            require(not Path(name).is_absolute() and '..' not in Path(name).parts, 'Unsafe payload path')
            raw = read(CANDIDATE/role/'agentporter'/name)
            require(sha(raw) == row['after_sha256'], 'Candidate payload changed')
            path = NEW[role]/SITE/name
            path.parent.mkdir(parents=True, exist_ok=True)
            atomic(path, raw, mode=0o444)
        # Keep wheel RECORD truthful for changed/new package members.
        import csv, io
        record = NEW[role]/SITE.parent/'agentporter-0.1.0.dev0.dist-info/RECORD'
        rows = list(csv.reader(io.StringIO(read(record).decode())))
        changes = manifest['roles'][role]['changed_files']
        rows = [r for r in rows if not (r and r[0].startswith('agentporter/') and r[0][12:] in changes)]
        for name in changes:
            raw = read(NEW[role]/SITE/name)
            rows.append(['agentporter/'+name, 'sha256='+base64.urlsafe_b64encode(hashlib.sha256(raw).digest()).decode().rstrip('='), str(len(raw))])
        output = io.StringIO(); csv.writer(output, lineterminator='\n').writerows(rows)
        atomic(record, output.getvalue().encode(), mode=0o444)
        release = json.loads(read(NEW[role]/'RELEASE.json'))
        release.update(version=NEW[role].name, previous_version=OLD[role].name,
            build_method='sealed_v14_plus_bcc_consolidation_overlay', application_delta_sha256=sha(manifest_raw),
            deployment_scope='BCC native account access-only broker; owner-run Git; Qman exact live scope')
        release['base_binary_inputs'] = release.pop('binary_inputs', {})
        release['binary_inputs'] = {}
        release['cli_layout'] = 'No embedded CLI copies; executable paths are fixed by protected worker configuration.'
        for directory, _, files in os.walk(NEW[role], topdown=False):
            for name in files:
                p = Path(directory)/name
                if not p.is_symlink():
                    p.chmod(0o555 if p.stat().st_mode & 0o111 else 0o444)
            Path(directory).chmod(0o555)
        release['files'] = helper.files_manifest(NEW[role])
        (NEW[role]).chmod(0o755)
        atomic(NEW[role]/'RELEASE.json', json.dumps(release, sort_keys=True, indent=2).encode()+b'\n', mode=0o444)
        NEW[role].chmod(0o555)
        require(json.loads(read(NEW[role]/'RELEASE.json'))['files'] == helper.files_manifest(NEW[role]), 'Sealed release validation failed')
        state.setdefault('new', {})[role] = {'fingerprint': helper.fingerprint(NEW[role]/SITE),
            'manifest_sha256': sha(read(NEW[role]/'RELEASE.json'))}
        save(state, 'sealed_'+role)
    # Freeze operator templates; no account data is present in them.
    for p in (CANDIDATE/'operator').iterdir():
        raw = read(p)
        require(sha(raw) == manifest['operator_files'][p.name], 'Operator template changed')
        atomic(CONTROL/'payload'/p.name, raw, mode=0o444)
    own = read(Path(__file__))
    require(sha(own) == globals().get('BOOTSTRAP_SHA'), 'Rollout source changed during root staging')
    atomic(CONTROL/'rollout.py', own, mode=0o500)
    save(state, 'staged')


def snapshot_replace(state, path, raw, uid=0, gid=0, mode=0o600):
    key = str(path)
    require(not path.is_symlink(), 'Refuse symlink configuration')
    if key not in state['files']:
        if path.exists():
            old = read(path); info = path.stat()
            backup = str(len(state['files']))+'.backup'
            atomic(CONTROL/backup, old)
            state['files'][key] = {'backup': backup, 'before_sha256': sha(old),
                'uid': info.st_uid, 'gid': info.st_gid, 'mode': stat.S_IMODE(info.st_mode)}
        else:
            state['files'][key] = {'backup': None, 'before_sha256': None}
    row = state['files'][key]
    expected = row.get('after_sha256', row['before_sha256'])
    require((sha(read(path)) if path.exists() else None) == expected, 'Concurrent owner configuration change retained')
    row['after_sha256'] = sha(raw)
    save(state, 'replacement_intent')
    atomic(path, raw, uid, gid, mode)


def enroll_accounts():
    policy = json.loads(read(CONTROL/'payload/credential-broker.json'))
    identities = set()
    legacy = Path('/var/lib/agentporter-bcc-worker/staging/bcc-stage-20261027-03/credentials')
    for name, spec in policy['accounts'].items():
        raw = read(Path(spec['auth_file']))
        data = json.loads(raw)
        expected = json.loads(read(legacy/name/'.codex/auth.json'))['tokens']['account_id']
        require(data.get('auth_mode') in (None, 'chatgpt') and not data.get('OPENAI_API_KEY')
            and data['tokens']['account_id'] == expected and isinstance(expected, str), 'Native/worker account binding changed')
        require(expected not in identities, 'Intended distinct native accounts unexpectedly alias')
        identities.add(expected)
        spec['account_id'] = expected
    return policy


def configure(helper, state):
    # Patch only explicit controls; preserve every other current field.
    for role in OLD:
        path = CONFIG[role]/'action-policy.yaml'
        policy = yaml.safe_load(read(path))
        policy.setdefault('action_modes', {}).update(git_commit='LOCKED', git_push='LOCKED')
        snapshot_replace(state, path, yaml.safe_dump(policy, sort_keys=False).encode(), helper.ROLES[role]['uid'], helper.ROLES[role]['gid'])
    path = CONFIG['worker']/'development-runtime.yaml'
    runtime = yaml.safe_load(read(path))
    delta = json.loads(read(CONTROL/'payload/worker-config-delta.json'))
    for name, change in delta.items():
        spec = runtime['workers'][name]
        require(change['remove_credential'] in spec['credentials'], 'Expected legacy worker credential reference missing')
        del spec['credentials'][change['remove_credential']]
        spec.update({key: value for key, value in change.items() if key != 'remove_credential'})
    snapshot_replace(state, path, yaml.safe_dump(runtime, sort_keys=False).encode(), WORKER, WORKER)
    policy = enroll_accounts()
    snapshot_replace(state, AUTH_POLICY, json.dumps(policy, indent=2).encode(), mode=0o644)
    unit = read(CONTROL/'payload/agentporter-bcc-credential-broker.service.in').replace(b'@RELEASE_PYTHON@', str(NEW['worker']/'venv/bin/python').encode())
    require(b'@' not in unit and b'PrivateTmp=no' in unit, 'Unresolved broker unit')
    snapshot_replace(state, AUTH_UNIT, unit, mode=0o644)
    if not AUTH_STATE.exists():
        AUTH_STATE.mkdir(mode=0o700)
        os.chown(AUTH_STATE, OWNER, GROUP)
    info = AUTH_STATE.stat()
    require(info.st_uid == OWNER and stat.S_IMODE(info.st_mode) == 0o700, 'Unsafe broker state custody')
    for role in OLD:
        path = helper.unit_path(role)
        body = read(path)
        old = str(OLD[role]).encode()+b'/venv/bin/python'
        require(body.count(old) == 1, 'Production entry point changed')
        body = body.replace(old, str(NEW[role]).encode()+b'/venv/bin/python')
        if role == 'worker':
            body += b'\n[Unit]\nRequires=agentporter-bcc-credential-broker.service\nAfter=agentporter-bcc-credential-broker.service\n'
        snapshot_replace(state, path, body, mode=0o644)
    before, after, corrections = catalog_correction(helper)
    if corrections:
        require(sha(before) == state['baseline']['catalog']['sha256'], 'Catalog changed during cutover')
        snapshot_replace(state, helper.COMMON, after, mode=0o644)
        state['catalog_corrections'] = corrections
    helper.PLAN['common_manifest'] = {'identity': helper.identity(helper.COMMON), 'raw_hex': read(helper.COMMON).hex()}
    helper.profile_snapshot()


def stop_pair(helper, state):
    before = {r: helper.show(r) for r in OLD}
    system('stop', *(helper.ROLES[r]['unit'] for r in OLD))
    for role in OLD:
        helper.stopped(role, before[role])
        helper.guard(role, 'check', state['nonce'], state['baseline']['databases'][role])


def release_guards(helper, state):
    for role in list(state['guarded']):
        helper.guard(role, 'remove', state['nonce'], state['baseline']['databases'][role])
        state['guarded'].remove(role)
        save(state, 'admission_released_'+role)
    helper.resume_timer(state)


def restore(helper, state, *, release=True):
    # Refuse to discard later owner edits or stop active jobs during rollback.
    for name, row in state['files'].items():
        p = Path(name)
        require((sha(read(p)) if p.exists() else None) in {row['before_sha256'], row.get('after_sha256'), row.get('rollback_sha256')},
            'Rollback would overwrite owner edits; retain journal')
    stop_pair(helper, state)
    if AUTH_UNIT.exists():
        system('stop', AUTH_UNIT.name)
    for name, row in reversed(list(state['files'].items())):
        p = Path(name)
        if row['backup'] is None:
            if p.exists():
                p.unlink()
        else:
            # A narrower project permission remains authoritative on rollback.
            # Restoring the obsolete catalog mode would break the old release.
            if p == helper.COMMON and state.get('catalog_corrections'):
                continue
            if p.name == 'action-policy.yaml' and p.parent in CONFIG.values():
                # Never reopen Git or raw execution while rehearsing the old
                # version. The original v14 code grants commits to writers.
                # Old-version health/source checks need no mutation authority.
                policy = yaml.safe_load(read(CONTROL/row['backup']))
                policy.setdefault('action_modes', {}).update(git_commit='LOCKED', git_push='LOCKED',
                    exec_run='LOCKED', exec_start='LOCKED', dispatch_agent='LOCKED')
                body = yaml.safe_dump(policy, sort_keys=False).encode()
                row['rollback_sha256'] = sha(body)
                save(state, 'rollback_policy_intent')
                atomic(p, body, row['uid'], row['gid'], row['mode'])
                continue
            atomic(p, read(CONTROL/row['backup']), row['uid'], row['gid'], row['mode'])
    system('daemon-reload')
    system('start', *(helper.ROLES[r]['unit'] for r in OLD))
    for role in OLD:
        live(helper, role, OLD[role], state['baseline']['releases'][role]['fingerprint'])
    save(state, 'old_release_verified')
    if release:
        release_guards(helper, state)
        save(state, 'rolled_back')


def apply(helper, state):
    require(state['phase'] == 'staged', 'Apply requires the staged generation')
    require(baseline(helper) == state['baseline'], 'Baseline changed after staging; rebind and review')
    for role in OLD:
        require(sha(read(NEW[role]/'RELEASE.json')) == state['new'][role]['manifest_sha256']
            and json.loads(read(NEW[role]/'RELEASE.json'))['files'] == helper.files_manifest(NEW[role]), 'Sealed candidate drift')
        live(helper, role, OLD[role], state['baseline']['releases'][role]['fingerprint'])
    helper.begin_timer_cycle(state)
    try:
        for role in OLD:
            # Intent before guard mutation supports inspection after interruption.
            save(state, 'admission_guard_intent_'+role)
            helper.guard(role, 'ensure', state['nonce'], state['baseline']['databases'][role])
            state['guarded'].append(role)
            save(state, 'admission_guarded_'+role)
        helper.pause_timer(state)
        stop_pair(helper, state)
        save(state, 'pair_stopped')
        configure(helper, state)
        system('daemon-reload')
        system('start', AUTH_UNIT.name)
        system('start', *(helper.ROLES[r]['unit'] for r in OLD))
        state['new_pids'] = {r: live(helper, r, NEW[r], state['new'][r]['fingerprint']) for r in OLD}
        save(state, 'new_release_verified')
        # Rehearse the old pair with admissions held, then restore the new pair.
        after = {name: read(Path(name)) for name in state['files']}
        restore(helper, state, release=False)
        stop_pair(helper, state)
        for name, raw in after.items():
            path = Path(name)
            role = next((r for r in OLD if path.parent == CONFIG[r]), None)
            uid = helper.ROLES[role]['uid'] if role else 0
            gid = helper.ROLES[role]['gid'] if role else 0
            mode = 0o600 if role else 0o644
            atomic(path, raw, uid, gid, mode)
        system('daemon-reload')
        system('start', AUTH_UNIT.name)
        system('start', *(helper.ROLES[r]['unit'] for r in OLD))
        state['new_pids'] = {r: live(helper, r, NEW[r], state['new'][r]['fingerprint']) for r in OLD}
        helper.profile_snapshot()
        save(state, 'rollback_rehearsal_passed')
        release_guards(helper, state)
        save(state, 'active_pending_live_acceptance')
    except BaseException:
        save(state, 'activation_failed')
        if state['files']:
            restore(helper, state)
        else:
            release_guards(helper, state)
            save(state, 'refused_before_switch')
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--stage', action='store_true')
    parser.add_argument('--apply', action='store_true')
    parser.add_argument('--rollback', action='store_true')
    args = parser.parse_args()
    require(sum((args.stage,args.apply,args.rollback)) <= 1, 'Choose one rollout operation')
    require(os.getuid() == 0 and sys.flags.isolated and sys.flags.dont_write_bytecode, 'Use owner sudo and isolated Python -I -B')
    require(socket.gethostname().split('.')[0] == 'pho-rdpdl-23', 'BCC only')
    helper = controls()
    with helper.operation_locks():
        if args.stage:
            require(sha(read(Path(__file__))) == globals().get('BOOTSTRAP_SHA'), 'Use the hash-bound staging bootstrap')
            stage(helper, {})
        elif args.apply or args.rollback:
            require(Path(__file__) in {CONTROL/'rollout.py', CONTROL/'rollout-v2.py'}, 'Use the sealed installed rollout copy')
            helper.root_path(Path(__file__), leaf_file=True)
            state = json.loads(read(STATE))
            if args.apply:
                apply(helper, state)
            else:
                require(state['phase'] == 'active_pending_live_acceptance', 'Rollback requires an active known generation')
                state['nonce'] = secrets.token_hex(16)
                helper.begin_timer_cycle(state)
                for role in OLD:
                    helper.guard(role,'ensure',state['nonce'],state['baseline']['databases'][role])
                    state['guarded'].append(role)
                helper.pause_timer(state)
                restore(helper, state)
        else:
            value = baseline(helper)
            print(json.dumps({'plan_only': True, 'services_changed': False, 'credentials_changed': False,
                'baseline': value, 'new_releases': {r:str(p) for r,p in NEW.items()},
                'git_workflow': 'B6 commit/push LOCKED; owner Git after explicit chat approval'}))


if __name__ == '__main__':
    main()
