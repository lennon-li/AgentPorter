#!/usr/bin/python3
"""Owner-only enrollment of the disposable mapped fixture; plan by default."""
import argparse, atexit, hashlib, json, os
from pathlib import Path
import secrets, stat, subprocess, tempfile, time, urllib.request
import yaml

DATA = Path('/var/lib/agentporter-bcc-worker/staging/bcc-stage-20261027-03')
CONFIG = DATA / 'config'
STATE = Path('/var/lib/agentporter-bcc-stage-operator/enroll-owner-fixture')
SOURCE = Path('/home/yeli/repos/AgentPorter/artifacts/bcc-acceptance-current/owner-fixture')
SERVICE = 'agentporter-bcc-worker.service'
CONFIG_FD = None
FILES = ('config.yaml', 'workspaces.yaml', 'public-client-policy.yaml', 'development-runtime.yaml')
GUARD_PROGRAM = '\nimport json,re,sqlite3,sys\ndatabase,action,nonce=sys.argv[1:]\nassert re.fullmatch(\'[0-9a-f]{32}\',nonce)\nassert action in {\'install\',\'check\',\'remove\'}\nterminal=(\'completed\',\'failed\',\'cancelled\',\'timed_out\',\'output_limit_exceeded\',\'interrupted\',\'recovered\')\nsql={name:"CREATE TRIGGER "+name+" BEFORE "+operation+" ON job_admissions BEGIN SELECT RAISE(ABORT,\'BCC staging update "+nonce+"\'); END"\n     for name,operation in [(\'bcc_stage_update_insert\',\'INSERT\'),(\'bcc_stage_update_update\',\'UPDATE\')]}\nwith sqlite3.connect(\'file:\'+database+\'?mode=rw\',uri=True,timeout=3) as db:\n    db.execute(\'BEGIN IMMEDIATE\')\n    assert db.execute(\'SELECT count(*) FROM job_admissions\').fetchone()[0]==0,\'Unresolved admissions\'\n    rows=db.execute(\'SELECT status FROM jobs\').fetchall()\n    assert all(row[0] in terminal for row in rows),\'Active or unresolved jobs\'\n    actual=dict(db.execute("SELECT name,sql FROM sqlite_master WHERE type=\'trigger\' AND name IN (?,?)",tuple(sql)))\n    if action==\'install\':\n        assert not actual,\'Unknown or prior guard already present\'\n        for statement in sql.values(): db.execute(statement)\n    else:\n        assert actual==sql,\'Guard ownership/SQL mismatch\'\n        if action==\'remove\':\n            for name in sql: db.execute(\'DROP TRIGGER \'+name)\nprint(json.dumps({\'guard\':action,\'jobs_terminal\':True,\'admissions\':0}))\n'


class StrictLoader(yaml.SafeLoader):
    def compose_node(self, parent, index):
        if self.check_event(yaml.AliasEvent) or self.peek_event().anchor is not None:
            raise ValueError('Configuration YAML anchors and aliases are forbidden')
        return super().compose_node(parent,index)


def unique_mapping(loader,node,deep=False):
    result = {}
    for key_node,value_node in node.value:
        key = loader.construct_object(key_node,deep=deep)
        if not isinstance(key,str) or key in result:
            raise ValueError('Duplicate or nonstring configuration key')
        result[key] = loader.construct_object(value_node,deep=deep)
    return result

StrictLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,unique_mapping)


def require(ok, message):
    if not ok: raise PermissionError(message)


def root_control(path):
    info = path.lstat()
    require(not stat.S_ISLNK(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022,
            'Untrusted owner-controlled path: ' + str(path))


def configuration_path(name):
    require(name in FILES and CONFIG_FD is not None, 'Unpinned configuration access')
    return Path(f'/proc/self/fd/{CONFIG_FD}') / name


def pin_configuration():
    global CONFIG_FD
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
    fd = os.open('/', flags)
    try:
        for component in CONFIG.parts[1:]:
            child = os.open(component, flags, dir_fd=fd)
            os.close(fd); fd = child
            info = os.fstat(fd)
            require(info.st_uid in (0,997) and not info.st_mode & 0o022, 'Untrusted configuration ancestor')
        CONFIG_FD, fd = fd, None
        atexit.register(os.close, CONFIG_FD)
    finally:
        if fd is not None: os.close(fd)


def configuration_bytes(name):
    fd = os.open(name, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=CONFIG_FD)
    try:
        info = os.fstat(fd)
        require(stat.S_ISREG(info.st_mode) and info.st_uid in (0,997) and not info.st_mode & 0o022
                and info.st_size < 65536, 'Untrusted configuration file')
        return os.read(fd,65536), info
    finally: os.close(fd)


def prepare_documents(documents, view):
    documents = __import__('copy').deepcopy(documents)
    documents['config.yaml'].setdefault('sandbox', {})['workspace_transactions'] = True
    rows = documents['workspaces.yaml']['workspaces']
    require('bcc-owner-fixture' not in rows, 'Fixture already enrolled; inspect before applying again')
    rows['bcc-owner-fixture'] = {'path': str(view), 'writable': True,
        'allow_execute': True, 'allow_agent_dispatch': True,
        'description': 'Disposable owner-owned mapped acceptance fixture'}
    documents['public-client-policy.yaml']['workspaces']['bcc-owner-fixture'] = {
        'path': str(view), 'operations': ['read', 'write', 'exec', 'git_read', 'dispatch', 'dispatch_write']}
    runtime = documents['development-runtime.yaml']
    require(runtime.get('public_client_policy_required') is True and runtime.get('egress_policy') == 'provider_origin',
            'Expected confined provider-origin runtime')
    require(all(row['path'] != str(view) for row in runtime['allowed_workspace_roots']), 'View already admitted')
    runtime['allowed_workspace_roots'].append({'path': str(view), 'writable': True})
    return documents


def atomic(path, body, metadata):
    fd, temporary = tempfile.mkstemp(dir=path.parent)
    try:
        os.fchmod(fd, metadata['mode'])
        os.fchown(fd, metadata['uid'], metadata['gid'])
        with os.fdopen(fd, 'wb') as stream:
            stream.write(body); stream.flush(); os.fsync(stream.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try: os.fsync(directory)
        finally: os.close(directory)
    finally:
        if os.path.exists(temporary): os.unlink(temporary)


def guard(action, nonce):
    result = subprocess.run(['/usr/bin/python3', '-I', '-c', GUARD_PROGRAM,
        str(DATA / 'state/jobs.db'), action, nonce], user=997, group=997, extra_groups=(),
        cwd='/', env={'PATH':'/usr/bin:/bin','HOME':str(DATA/'home'),'LANG':'C.UTF-8'},
        capture_output=True, timeout=10)
    require(result.returncode == 0, 'Admission barrier refused; preserve state and inspect active jobs/guard')


def service(action):
    if action == 'start':
        current = CONFIG.stat(); pinned = os.fstat(CONFIG_FD)
        require((current.st_dev,current.st_ino) == (pinned.st_dev,pinned.st_ino), 'Configuration directory changed; keep service stopped')
    subprocess.run(['/usr/bin/systemctl', action, SERVICE], check=True, timeout=30)


def healthy():
    for attempt in range(30):
        try:
            with urllib.request.urlopen('http://127.0.0.1:8876/health', timeout=1) as response:
                if response.status == 200: return
        except OSError: pass
        time.sleep(.5)
    raise RuntimeError('Isolated gateway health did not recover')


def restore(manifest):
    for name, metadata in manifest['files'].items():
        body = (STATE / name).read_bytes()
        require(hashlib.sha256(body).hexdigest() == metadata['sha256'], 'Rollback backup changed')
        atomic(configuration_path(name), body, metadata)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--apply', action='store_true')
    parser.add_argument('--recover', action='store_true')
    parser.add_argument('--rollback', action='store_true')
    args = parser.parse_args()
    require(sum((args.apply,args.recover,args.rollback)) <= 1, 'Choose apply, recover or rollback')
    require(os.getuid() == 0 and os.geteuid() == 0, 'Owner sudo authentication required to inspect private config')
    for ancestor in reversed(Path(__file__).parents): root_control(ancestor)
    root_control(Path(__file__))
    pin_configuration()
    unit = subprocess.check_output(['/usr/bin/systemctl','show',SERVICE,'-p','ExecStart','--value'],text=True)
    require('/releases/bcc-stage-20261028-08/venv/bin/python' in unit, 'Expected running release-08 unit')
    if args.recover or args.rollback:
        root_control(STATE)
        manifest = json.loads((STATE / 'manifest.json').read_text())
        for name, metadata in manifest['files'].items():
            current = hashlib.sha256(configuration_bytes(name)[0]).hexdigest()
            require(current in {metadata['sha256'],metadata['proposed_sha256']}, 'Configuration changed outside enrollment; preserve owner edits')
        if args.rollback:
            manifest['nonce'] = secrets.token_hex(16)
            atomic(STATE/'manifest.json',json.dumps(manifest,sort_keys=True).encode(),{'uid':0,'gid':0,'mode':0o600})
            guard('install',manifest['nonce'])
        else:
            guard('check',manifest['nonce'])
        service('stop'); restore(manifest)
        service('start'); healthy(); guard('remove',manifest['nonce'])
        print('FIXTURE_CONFIG_RECOVERED; production and tunnel unchanged.'); return
    identity = SOURCE.stat()
    require(SOURCE.resolve() == SOURCE and identity.st_uid == 2056259175, 'Unexpected canonical fixture')
    view = Path('/var/lib/agentporter-bcc/publication-views') / f'{identity.st_dev:x}-{identity.st_ino:x}'
    for ancestor in reversed(view.parents): root_control(ancestor)
    mapped = view.lstat()
    require(stat.S_ISDIR(mapped.st_mode) and (mapped.st_dev,mapped.st_ino,mapped.st_uid,mapped.st_gid) ==
        (identity.st_dev,identity.st_ino,997,997) and not os.statvfs(view).f_flag & os.ST_RDONLY,
        'Provisioned publication view identity/access mismatch')
    original = {}; metadata = {}; documents = {}
    for name in FILES:
        body, info = configuration_bytes(name)
        require(stat.S_ISREG(info.st_mode) and info.st_uid in (0,997) and not info.st_mode & 0o022,
                'Untrusted existing configuration file')
        require(len(body) < 65536, 'Oversized configuration')
        original[name] = body
        metadata[name] = {'uid':info.st_uid,'gid':info.st_gid,'mode':stat.S_IMODE(info.st_mode),
                          'sha256':hashlib.sha256(body).hexdigest()}
        documents[name] = yaml.load(body, Loader=StrictLoader)
    proposed = prepare_documents(documents, view)
    serialized = {name:yaml.safe_dump(document,sort_keys=True).encode() for name,document in proposed.items()}
    for name in FILES: metadata[name]['proposed_sha256'] = hashlib.sha256(serialized[name]).hexdigest()
    print(json.dumps({'workspace':'bcc-owner-fixture','mapped_root':str(view),
        'workspace_transactions':True,'mode':'apply' if args.apply else 'plan','production_changed':False}))
    if not args.apply: return
    require(not STATE.exists(), 'Prior enrollment journal exists; use recovery or inspect')
    for ancestor in reversed(STATE.parent.parents): root_control(ancestor)
    root_control(STATE.parent)
    STATE.mkdir(mode=0o700)
    nonce = secrets.token_hex(16)
    manifest = {'nonce':nonce,'files':metadata}
    private = {'uid':0,'gid':0,'mode':0o600}
    for name, body in original.items(): atomic(STATE / name, body, private)
    atomic(STATE/'manifest.json',json.dumps(manifest,sort_keys=True).encode(),private)
    guarded = False
    try:
        guard('install', nonce); guarded = True
        service('stop')
        for name, body in original.items():
            require(configuration_bytes(name)[0] == body, 'Config changed after review; refuse overwrite')
        for name, document in proposed.items():
            atomic(configuration_path(name), serialized[name],metadata[name])
        service('start'); healthy(); guard('remove',nonce); guarded=False
    except BaseException:
        if guarded:
            service('stop'); restore(manifest); service('start'); healthy(); guard('remove',nonce)
        raise
    print('OWNER_FIXTURE_ENROLLED: transactional staging config healthy; production/tunnel unchanged.')


if __name__ == '__main__': main()
