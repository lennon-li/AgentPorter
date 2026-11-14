"""Private worker Git state with a fixed, offline history import boundary.

Workers never write canonical metadata. Bounded validated local refs, object
data, the staged index tree and stash stack cross back only after job cleanup.
Repository configuration, hooks and protected ref namespaces never copy back.
"""
import json
import os
from pathlib import Path
import stat
import subprocess
import time

from agentporter.git_approval_state import _INSPECT
from agentporter.git_commits import _MetadataMount, _inspect_metadata, _mount_id
from agentporter.resources import ResourceCleanupError
from agentporter.sandbox.workspace_delta import _file_signature as _guard_signature
from agentporter.workspaces.leases import mutation_lease, workspace_key

_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC

# Runs only over the independent private copy, offline and resource supervised,
# before that metadata can be exposed to worker/provider code. No hooks/config
# from the source repository enter this validator.
_VALIDATE_SHARED_OBJECTS = r'''
import hashlib, json, os, re, stat, subprocess, sys
paths = json.loads(sys.argv[1]); length = int(sys.argv[2]); width = length // 2
assert length in (40,64) and len(paths) <= 1000000
root = '/workspace/.git/'
def trailer_hash(path, trailers):
    fd = os.open(root + path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        assert stat.S_ISREG(before.st_mode) and before.st_nlink == 1
        assert width * trailers <= before.st_size <= 640 * 1024 * 1024
        h = hashlib.sha1() if length == 40 else hashlib.sha256()
        remaining = before.st_size - width
        while remaining:
            data = os.read(fd,min(65536,remaining)); assert data
            h.update(data); remaining -= len(data)
        last = os.read(fd,width); assert last == h.digest()
        os.lseek(fd,-width*trailers,os.SEEK_END)
        result = os.read(fd,width)
        after = os.fstat(fd)
        assert all(getattr(after,k)==getattr(before,k) for k in
            ('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns'))
        return result.hex()
    finally: os.close(fd)
environment = {'PATH':'/usr/bin:/bin','HOME':'/nonexistent','LANG':'C','LC_ALL':'C',
    'GIT_CONFIG_NOSYSTEM':'1','GIT_CONFIG_GLOBAL':'/dev/null','GIT_ALLOW_PROTOCOL':'',
    'GIT_NO_LAZY_FETCH':'1','GIT_NO_REPLACE_OBJECTS':'1','GIT_TERMINAL_PROMPT':'0','GIT_OPTIONAL_LOCKS':'0'}
base = ['/usr/bin/git','-c','safe.directory=/workspace','-c','core.hooksPath=/dev/null',
        '-c','core.fsmonitor=false','-c','protocol.allow=never','--git-dir=/workspace/.git']
for path in paths:
    if path.startswith('objects/pack/'):
        match = re.fullmatch(r'objects/pack/pack-([0-9a-f]+)\.(pack|idx)',path)
        assert match and len(match[1]) == length
        stem = 'objects/pack/pack-' + match[1]
        assert trailer_hash(stem+'.pack',1) == match[1]
        assert trailer_hash(stem+'.idx',2) == match[1]
        subprocess.run(base+['verify-pack',root+stem+'.idx'],env=environment,check=True,
            stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=15)
    else:
        assert re.fullmatch(r'objects/[0-9a-f]{2}/[0-9a-f]+',path)
        assert len(path.removeprefix('objects/').replace('/','')) == length
# fsck --full checks even unreachable loose objects against their OID paths.
subprocess.run(base+['fsck','--full','--strict','--no-reflogs','--no-dangling'],
    env=environment,check=True,stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,
    stderr=subprocess.DEVNULL,timeout=15)
print('SHARED_GIT_OBJECTS_VERIFIED')
'''

_HISTORY_INSPECT = r'''
import contextlib, io, json, os, re, stat, subprocess
ns = {}
with contextlib.redirect_stdout(io.StringIO()):
    exec(''' + repr(_INSPECT) + r''', ns)
environment, base = ns['environment'], ns['base']
environment = dict(environment, GIT_DIR='/workspace/.git', GIT_WORK_TREE='/workspace')
def checked(args, *, limit=65536):
    output = subprocess.run(base + args, env=environment, stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=10, check=True).stdout
    if len(output) > limit:
        raise RuntimeError('Local Git state exceeds inspection budget')
    return output
length = 40 if ns['kind'] == 'sha1' else 64
def oid(value, *, zero=False):
    return (len(value) == length and all(c in '0123456789abcdef' for c in value)
            and (zero or value != '0' * length))
refs = {}
for line in checked(['for-each-ref', '--format=%(refname)%00%(objectname)%00%(symref)']).splitlines():
    name, target, symbolic = line.decode('utf-8').split('\0')
    if (len(refs) >= 128 or len(name.encode()) > 256 or not oid(target)
            or name in refs or not name.startswith('refs/')):
        raise RuntimeError('Invalid or excessive Git refs')
    checked(['check-ref-format', name], limit=0)
    local = name.startswith(('refs/heads/', 'refs/tags/')) or name == 'refs/stash'
    if local and symbolic:
        raise RuntimeError('Local symbolic refs are unsupported')
    refs[name] = {'oid': target, 'symref': symbolic or None}
stash = ''
try:
    fd = os.open('/workspace/.git/logs/refs/stash', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
except FileNotFoundError:
    pass
else:
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > 16384:
            raise RuntimeError('Invalid stash reflog')
        data = os.read(fd, 16385)
        if len(data) != info.st_size:
            raise RuntimeError('Stash reflog changed during inspection')
        stash = data.decode('utf-8')
    finally:
        os.close(fd)
    records = stash.splitlines(keepends=True)
    if len(records) > 64:
        raise RuntimeError('Stash stack exceeds inspection budget')
    for line in records:
        match = re.fullmatch(r'([0-9a-f]+) ([0-9a-f]+) ([^\x00\n\r\t]+) <([^<>\x00\n\r\t]*)> ([0-9]{1,20}) ([+-][0-9]{4})\t([^\x00\n\r]*)\n', line)
        if (not match or not oid(match[1], zero=True) or not oid(match[2])
                or len(line.encode()) > 1024):
            raise RuntimeError('Unsupported stash reflog record')
        if checked(['cat-file', '-t', match[2]], limit=32).strip() != b'commit':
            raise RuntimeError('Stash reflog target is not a commit')
        if match[1] != '0' * length and checked(['cat-file', '-t', match[1]], limit=32).strip() != b'commit':
            raise RuntimeError('Stash reflog prior target is not a commit')
    if (not records or 'refs/stash' not in refs
            or records[-1].split(' ', 2)[1] != refs['refs/stash']['oid']):
        raise RuntimeError('Stash ref and reflog disagree')
if 'refs/stash' in refs and not stash:
    raise RuntimeError('Stash ref lacks its stack')
state = {key: ns[key] for key in ('head', 'branch', 'tree')}
state.update(refs=refs, stash_log=stash)
encoded = json.dumps(state, sort_keys=True)
if len(encoded.encode()) > 60000:
    raise RuntimeError('Git state exceeds publication budget')
print(encoded)
'''

_EXCLUDED_GIT_PATHSPEC = ':(top,literal).venv'
_MAX_EXCLUDED_GIT_OUTPUT = 4 * 1024 * 1024


def _reject_excluded_git_paths(
    git_dir: Path, workspace: Path | None = None, *, pass_fds: tuple[int, ...] = (),
) -> None:
    """Reject index or reachable-history entries hidden from the worktree."""
    env = {
        'PATH': '/usr/bin:/bin',
        'HOME': '/nonexistent',
        'LANG': 'C',
        'LC_ALL': 'C',
        'GIT_CONFIG_NOSYSTEM': '1',
        'GIT_CONFIG_GLOBAL': '/dev/null',
        'GIT_NO_LAZY_FETCH': '1',
        'GIT_NO_REPLACE_OBJECTS': '1',
        'GIT_TERMINAL_PROMPT': '0',
        'GIT_OPTIONAL_LOCKS': '0',
        'GIT_ALLOW_PROTOCOL': '',
    }
    base = ['/usr/bin/git', f'--git-dir={git_dir}']
    if workspace is not None:
        base.append(f'--work-tree={workspace}')
    base.extend([
        '-c', 'core.fsmonitor=false', '-c', 'core.hooksPath=/dev/null',
        '-c', 'protocol.allow=never',
    ])
    checks = (
        ['ls-files', '-z', '--', _EXCLUDED_GIT_PATHSPEC],
        ['log', '--all', '--reflog', '--full-history', '--format=%H', '-z', '--',
         _EXCLUDED_GIT_PATHSPEC],
    )
    for args in checks:
        try:
            result = subprocess.run(
                base + args,
                env=env,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                timeout=20,
                check=False,
                pass_fds=pass_fds,
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            raise PermissionError('Private Git excluded-path inspection failed') from error
        if result.returncode != 0 or len(result.stdout) > _MAX_EXCLUDED_GIT_OUTPUT:
            raise PermissionError('Private Git excluded-path inspection failed')
        if result.stdout:
            raise PermissionError('Git metadata references excluded .venv paths')


_PULL_REF_CHECK = r'''
import hashlib
def checked_pull_tracking(before, after, approved):
    def ordinary(name):
        return name.startswith(('refs/heads/', 'refs/tags/')) or name == 'refs/stash'
    tracking = None
    if approved is not None:
        auth = approved['authorization']; request = auth['request']; params = request['parameters']
        encoded = json.dumps(request, sort_keys=True, separators=(',', ':'), ensure_ascii=True, allow_nan=False).encode()
        local=auth.get('version')==2 and auth.get('authorization_mode')=='workspace'
        if (auth['version'] not in ((2,) if local else (1,)) or request['operation'] not in (('pull','fetch') if local else ('pull',))
                or hashlib.sha256(b'AgentPorter Git request v1\0' + encoded).hexdigest() != auth['request_sha256']
                or params['mode'] not in ('ff-only', 'merge', 'rebase')):
            raise RuntimeError('Invalid consumed pull plan')
        tracking = params['tracking_ref']
        expected_name = 'refs/remotes/' + params['remote_id'] + '/' + params['remote_ref'].removeprefix('refs/heads/')
        if (not params['remote_ref'].startswith('refs/heads/') or tracking != expected_name
                or params['remote_oid'] != params['new_oid']):
            raise RuntimeError('Pull tracking scope differs from signed remote')
        redundant = {key:request[key] for key in ('repository_device','repository_inode')}
        redundant.update({key:params[key] for key in ('metadata_device','metadata_inode','tracking_ref',
            'old_oid','new_oid','pack_sha256','policy_sha256','mode')})
        if auth['tracking'] != redundant:
            raise RuntimeError('Pull tracking authority differs from signed request')
        signed = params['canonical_state']
        if any(before[key] != signed[key] for key in ('head','branch','tree')):
            raise RuntimeError('Pull canonical baseline differs from signed request')
        old = None if set(params['old_oid']) == {'0'} else {'oid':params['old_oid'],'symref':None}
        new = {'oid':params['new_oid'],'symref':None}
        if before['refs'].get(tracking) != old or after['refs'].get(tracking) != new:
            raise RuntimeError('Pull tracking transition differs from consumed exact authority')
    def protected(state, expected):
        result={}
        for name,value in state['refs'].items():
            if ordinary(name) or name==tracking:continue
            # A preserved symbolic ref resolves through the one authorized
            # tracking transition; its own target and presence stay exact.
            if tracking is not None and value.get('symref')==tracking:
                if value['oid']!=expected:raise RuntimeError('Protected symbolic ref resolved outside exact transition')
                value={'symref':tracking}
            result[name]=value
        return result
    if protected(before, params['old_oid'] if tracking else None)!=protected(after, params['new_oid'] if tracking else None):
        raise RuntimeError('Protected ref namespace changed')
    return tracking
'''

_EXPORT = r'''
import contextlib, io, json, os, resource, subprocess, sys
baseline = json.loads(sys.argv[1])
ns = {}
with contextlib.redirect_stdout(io.StringIO()):
    exec(sys.argv[2], ns)
state = json.loads(ns['encoded'])
head, branch, tree = state['head'], state['branch'], state['tree']
# APPROVED_PULL_REF_CHECK
approved_pull = json.loads(sys.argv[3]) if len(sys.argv)>3 else None
approved_tracking = checked_pull_tracking(baseline, state, approved_pull)
def local(name):
    return name.startswith(('refs/heads/', 'refs/tags/')) or name == 'refs/stash' or name == approved_tracking
if branch is not None and not branch.startswith('refs/heads/'):
    raise RuntimeError('HEAD must identify a local branch or detached commit')
env = dict(ns['environment'], GIT_DIR='/workspace/.git', GIT_WORK_TREE='/workspace')
base = ns['base']
resource.setrlimit(resource.RLIMIT_FSIZE, (268435456, 268435456))
scratch = '/exchange/pack-metadata'
clean = {key: value for key, value in env.items() if key not in {'GIT_DIR', 'GIT_WORK_TREE'}}
subprocess.run(base + ['init', '--quiet', '--bare', '--template=',
    '--object-format=' + ('sha1' if len(tree) == 40 else 'sha256'), scratch],
    env=clean, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
    stderr=subprocess.DEVNULL, timeout=10, check=True)
budget = 64 * 1024 * 1024
for name in ['index'] + [name for name in os.listdir('/workspace/.git') if name.startswith('sharedindex.')]:
    try:
        fd = os.open('/workspace/.git/' + name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    except FileNotFoundError:
        if name == 'index':
            continue
        raise
    try:
        import stat
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > budget:
            raise RuntimeError('Invalid index during object export')
        with open(scratch + '/' + name, 'xb') as target:
            while data := os.read(fd, 65536):
                budget -= len(data)
                if budget < 0:
                    raise RuntimeError('Git index export exceeds budget')
                target.write(data)
    finally:
        os.close(fd)
env = dict(clean, GIT_DIR=scratch, GIT_ALTERNATE_OBJECT_DIRECTORIES='/workspace/.git/objects')
generated = subprocess.run(base + ['write-tree'], env=env, stdin=subprocess.DEVNULL,
    stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=10, check=True).stdout.decode().strip()
if generated != tree:
    raise RuntimeError('Private index tree changed during export')
roots = {tree}
if head:
    roots.add(head)
roots.update(value['oid'] for name, value in state['refs'].items() if local(name))
for record in state['stash_log'].splitlines():
    old, new, _ = record.split(' ', 2)
    roots.add(new)
    if set(old) != {'0'}:
        roots.add(old)
revisions = ''.join(value + '\n' for value in sorted(roots))
# Every excluded object is already proven reachable from canonical baseline
# refs/HEAD or the validated baseline stash stack. This keeps large existing
# histories out of the bounded pack without assuming a fast-forward relation.
known = {value['oid'] for value in baseline['refs'].values()}
if baseline['head']:
    known.add(baseline['head'])
for record in baseline['stash_log'].splitlines():
    old, new, _ = record.split(' ', 2)
    known.add(new)
    if set(old) != {'0'}:
        known.add(old)
revisions += ''.join('^' + value + '\n' for value in sorted(known))
with open('/exchange/objects.pack', 'xb') as pack:
    subprocess.run(base + ['-c', 'pack.threads=1', '-c', 'pack.windowMemory=16m',
        'pack-objects', '--stdout', '--revs'], input=revisions.encode('ascii'),
        stdout=pack, stderr=subprocess.DEVNULL, env=env, timeout=20, check=True)
    pack.flush()
    os.fsync(pack.fileno())
print(json.dumps(state, sort_keys=True))
'''

_IMPORT = r'''
import contextlib, io, json, os, selectors, stat, subprocess, sys, tempfile, time
plan = json.loads(sys.argv[1])
ns = {}
with contextlib.redirect_stdout(io.StringIO()):
    exec(sys.argv[2], ns)
if json.loads(ns['encoded']) != plan['before']:
    raise RuntimeError('Canonical Git state changed during the job')
env = dict(ns['environment'], GIT_DIR='/workspace/.git', GIT_WORK_TREE='/workspace')
base = ns['base'] + ['-c', 'core.fsyncObjectFiles=true']
def run(args, **kwargs):
    return subprocess.run(base + args, env=env, stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL, timeout=20, check=True, **kwargs).stdout.decode().strip()
after = plan['after']
before = plan['before']
# APPROVED_PULL_REF_CHECK
approved_tracking = checked_pull_tracking(before, after, plan.get('approved_pull'))
def local(name):
    return name.startswith(('refs/heads/', 'refs/tags/')) or name == 'refs/stash' or name == approved_tracking
if after['branch'] is not None:
    if not after['branch'].startswith('refs/heads/'):
        raise RuntimeError('Invalid published HEAD branch')
    target = after['refs'].get(after['branch'])
    if (target is None and after['head'] is not None) or (target and target['oid'] != after['head']):
        raise RuntimeError('Published HEAD and branch disagree')
with open('/incoming/objects.pack', 'rb') as pack:
    run(['unpack-objects', '-r', '--strict'], stdin=pack)
# Validate imported identities with Git before any ref/index update.
run(['cat-file', '-e', after['tree'] + '^{tree}'])
if after['head']:
    run(['cat-file', '-e', after['head'] + '^{commit}'])
for name, target in after['refs'].items():
    if not local(name):
        continue
    run(['check-ref-format', name])
    if target['symref'] is not None:
        raise RuntimeError('Local symbolic refs are unsupported')
    kind = run(['cat-file', '-t', target['oid']])
    if name.startswith('refs/heads/') or name == 'refs/stash' or name == approved_tracking:
        if kind != 'commit':
            raise RuntimeError('Local branch/stash target is not a commit')
    elif kind not in {'commit', 'tag', 'tree', 'blob'}:
        raise RuntimeError('Invalid local tag target')
for record in after['stash_log'].splitlines():
    old, new, _ = record.split(' ', 2)
    run(['cat-file', '-e', new + '^{commit}'])
    if set(old) != {'0'}:
        run(['cat-file', '-e', old + '^{commit}'])
# Take native Git lockfile guards before inspecting again or staging an index.
# Keep the guard names until every metadata write has finished. Publishing a
# separate staged index must not remove index.lock and let stash push race.
git_root = '/workspace/.git'
directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
root_fd = os.open(git_root, directory_flags)
guards = {}
transaction = None
ref_scratch = None
staged_index = None
stash_ref_fd = None
stash_lock_fd = None
stash_temporary = None
def make_guard(name, parent=root_fd):
    fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                 0o600, dir_fd=parent)
    os.fsync(fd)
    return fd
def current_state():
    fresh = {}
    with contextlib.redirect_stdout(io.StringIO()):
        exec(sys.argv[2], fresh)
    return json.loads(fresh['encoded'])
def read_stash_log():
    try:
        fd = os.open(git_root + '/logs/refs/stash', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    except FileNotFoundError:
        return ''
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > 16384:
            raise RuntimeError('Invalid stash reflog during locked publication')
        data = os.read(fd, 16385)
        if len(data) != info.st_size:
            raise RuntimeError('Stash reflog changed during publication')
        return data.decode('utf-8')
    finally:
        os.close(fd)
def transaction_step(command, expected):
    transaction.stdin.write((command + '\n').encode('ascii'))
    transaction.stdin.flush()
    with selectors.DefaultSelector() as selector:
        selector.register(transaction.stdout, selectors.EVENT_READ)
        if not selector.select(20):
            raise RuntimeError('Git ref transaction acknowledgement timed out')
    if transaction.stdout.readline() != (expected + ': ok\n').encode('ascii'):
        raise RuntimeError('Git ref transaction failed before publication')

# Fixed publication identity makes the intermediate auto-generated stash log
# exactly derivable. A later owner drop/clear must not be mistaken for our own
# ref transaction's append after its locks are released.
publication_time = plan.get('publication_time', 0)
if type(publication_time) is not int or publication_time < 0:
    raise RuntimeError('Invalid Git publication timestamp')
env = dict(env, GIT_COMMITTER_NAME='AgentPorter',
           GIT_COMMITTER_EMAIL='agents@agentporter.invalid',
           GIT_COMMITTER_DATE='@' + str(publication_time) + ' +0000')
old_stash, new_stash = before['refs'].get('refs/stash'), after['refs'].get('refs/stash')
intermediate_stash = before['stash_log']
if old_stash != new_stash:
    if new_stash is None:
        intermediate_stash = ''
    else:
        old_oid = old_stash['oid'] if old_stash else '0' * len(new_stash['oid'])
        intermediate_stash += (old_oid + ' ' + new_stash['oid'] +
            ' AgentPorter <agents@agentporter.invalid> ' + str(publication_time) +
            ' +0000\tAgentPorter local Git publication\n')

commands = ['start']
for name in sorted(set(before['refs']) | set(after['refs'])):
    # Git applies each option to the next command, not the whole transaction.
    commands.append('option no-deref')
    old, new = before['refs'].get(name), after['refs'].get(name)
    if not local(name):
        # no-deref locks aliases independently of their concrete targets.
        commands.append('verify ' + name + ' ' + old['oid'])
    elif old is None:
        commands.append('create ' + name + ' ' + new['oid'])
    elif new is None:
        commands.append('delete ' + name + ' ' + old['oid'])
    elif old['oid'] == new['oid']:
        commands.append('verify ' + name + ' ' + old['oid'])
    else:
        commands.append('update ' + name + ' ' + new['oid'] + ' ' + old['oid'])
try:
    for name in ('index.lock', 'HEAD.lock'):
        guards[name] = make_guard(name)
    if current_state() != before:
        raise RuntimeError('Canonical Git state changed before locked publication')
    staged_index = '.agentporter-index-' + os.urandom(16).hex()
    index_environment = dict(env, GIT_INDEX_FILE=git_root + '/' + staged_index)
    result = subprocess.run(base + ['read-tree', after['tree']], env=index_environment,
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        timeout=20, check=True)
    # A trusted temporary per-worktree HEAD prevents update-ref from trying to
    # lock canonical HEAD implicitly when it updates its current branch. All
    # common refs/objects/logs still resolve to the canonical Git directory;
    # our separately held canonical HEAD.lock remains effective throughout.
    ref_scratch = tempfile.TemporaryDirectory(prefix='agentporter-ref-transaction-')
    scratch_head = before['head'] or after['head']
    if scratch_head is None:
        scratch_head = 'ref: refs/heads/agentporter-unborn-' + os.urandom(16).hex()
    with open(ref_scratch.name + '/HEAD', 'x') as scratch_file:
        scratch_file.write(scratch_head + '\n')
    # The commondir file is required by the supported files ref backend; the
    # environment override alone does not make this a linked metadata view.
    with open(ref_scratch.name + '/commondir', 'x') as scratch_common:
        scratch_common.write(git_root + '\n')
    ref_environment = dict(env, GIT_DIR=ref_scratch.name, GIT_COMMON_DIR=git_root)
    transaction = subprocess.Popen(base + ['update-ref', '--create-reflog', '-m',
        'AgentPorter local Git publication', '--stdin'], env=ref_environment,
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    transaction_step('start', 'start')
    for command in commands[1:]:
        transaction.stdin.write((command + '\n').encode('ascii'))
    transaction_step('prepare', 'prepare')
    # Git holds every ref's no-deref lock. Recheck both OID and symbolic type
    # now; old-OID CAS alone can accept a newly introduced symbolic alias.
    if current_state() != before:
        raise RuntimeError('Canonical Git ref identity changed while preparing publication')
    transaction_step('commit', 'commit')
    transaction.stdin.close()
    if transaction.wait(timeout=5):
        raise RuntimeError('Git ref transaction failed during publication')
    transaction = None

    if before['stash_log'] != after['stash_log']:
        # Native stash push is blocked by index.lock. Drop/clear use the stash
        # ref lock; if one won the brief reacquisition gap, preserve its exact
        # ref/log and refuse instead of overwriting it with the private stack.
        stash_ref_fd = os.open(git_root + '/refs', directory_flags)
        stash_lock_fd = make_guard('stash.lock', stash_ref_fd)
        observed = current_state()
        if (observed['refs'].get('refs/stash') != new_stash
                or observed['stash_log'] != intermediate_stash):
            raise RuntimeError('Owner stash state changed before locked stack publication')
        logs = os.open(git_root + '/logs', directory_flags)
        try:
            try:
                os.mkdir('refs', 0o700, dir_fd=logs)
            except FileExistsError:
                pass
            refs = os.open('refs', directory_flags, dir_fd=logs)
            try:
                if after['stash_log']:
                    stash_temporary = '.agentporter-stash-' + os.urandom(16).hex()
                    fd = make_guard(stash_temporary, refs)
                    try:
                        data = after['stash_log'].encode('utf-8')
                        offset = 0
                        while offset < len(data):
                            offset += os.write(fd, data[offset:])
                        os.fsync(fd)
                    finally:
                        os.close(fd)
                    os.replace(stash_temporary, 'stash', src_dir_fd=refs, dst_dir_fd=refs)
                    stash_temporary = None
                else:
                    try:
                        os.unlink('stash', dir_fd=refs)
                    except FileNotFoundError:
                        pass
                os.fsync(refs)
            finally:
                if stash_temporary is not None:
                    os.unlink(stash_temporary, dir_fd=refs)
                os.close(refs)
            os.fsync(logs)
        finally:
            os.close(logs)

    # Replace through distinct names so the native Git guards remain held.
    index_fd = os.open(staged_index, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
                       dir_fd=root_fd)
    try:
        os.fsync(index_fd)
    finally:
        os.close(index_fd)
    os.replace(staged_index, 'index', src_dir_fd=root_fd, dst_dir_fd=root_fd)
    staged_index = None
    head_value = ('ref: ' + after['branch'] if after['branch'] is not None else after['head']) + '\n'
    head_temporary = '.agentporter-head-' + os.urandom(16).hex()
    head_fd = make_guard(head_temporary)
    try:
        os.write(head_fd, head_value.encode('ascii'))
        os.fsync(head_fd)
    finally:
        os.close(head_fd)
    os.replace(head_temporary, 'HEAD', src_dir_fd=root_fd, dst_dir_fd=root_fd)
    os.fsync(root_fd)
    if current_state() != after:
        raise RuntimeError('Final Git state differs from the validated private state')
finally:
    if transaction is not None:
        try:
            transaction.stdin.close()
            transaction.wait(timeout=5)
        except (OSError, subprocess.TimeoutExpired):
            transaction.kill()
            transaction.wait(timeout=5)
    if ref_scratch is not None:
        ref_scratch.cleanup()
    if stash_lock_fd is not None:
        os.close(stash_lock_fd)
        os.unlink('stash.lock', dir_fd=stash_ref_fd)
    if stash_ref_fd is not None:
        os.close(stash_ref_fd)
    if staged_index is not None:
        try:
            os.unlink(staged_index, dir_fd=root_fd)
        except FileNotFoundError:
            pass
    for name, fd in guards.items():
        os.close(fd)
        os.unlink(name, dir_fd=root_fd)
    os.fsync(root_fd)
    os.close(root_fd)
# Persist metadata before the transaction can release its recovery guard.
for root, dirs, files in os.walk('/workspace/.git', followlinks=False):
    for name in files:
        fd = os.open(os.path.join(root, name), os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
print('WORKSPACE_GIT_IMPORTED')
'''


_EXPORT = _EXPORT.replace('# APPROVED_PULL_REF_CHECK', _PULL_REF_CHECK)
_IMPORT = _IMPORT.replace('# APPROVED_PULL_REF_CHECK', _PULL_REF_CHECK)
from agentporter.sandbox.native_git_journal import instrument
_IMPORT = instrument(_IMPORT)


def _copy_directory(source_fd, destination, budget, *, preflight=None):
    records = budget.preflight(source_fd, destination.parent) if preflight is None else preflight
    return budget.copy(source_fd, destination, records)


class _PrivateMount:
    wrap_argv = staticmethod(_MetadataMount.wrap_argv)

    def __init__(self, history, *, exchange=False):
        self.history, self.exchange = history, exchange
        self.launch_fds = (history.mount.root,)

    def wrap_command(self, command):
        h = self.history
        command = list(command)
        index = command.index(str(h.workspace))
        if command[index - 1] != '--ro-bind' or command[index + 1] != '/workspace':
            raise PermissionError('Private Git phase requires a read-only workspace')
        command[index] = f'/proc/self/fd/{h.mount.root}'
        command += ['--ro-bind', str(h.private), '/workspace/.git',
                    '--ro-bind', str(h.clean_config), '/workspace/.git/config']
        if self.exchange:
            command += ['--bind', str(h.exchange), '/exchange']
        return command


class _ImportMount:
    wrap_argv = staticmethod(_MetadataMount.wrap_argv)

    def __init__(self, history):
        self.history = history
        self.launch_fds = history.mount.launch_fds

    def wrap_command(self, command):
        return self.history.mount.wrap_command(command) + [
            '--ro-bind', str(self.history.exchange), '/incoming',
            '--bind', str(self.history.native_events), '/git-publication',
            '--ro-bind', str(self.history.native_events.parent/'native-git-provenance.so'), '/native-git-provenance.so']


class WorkspaceGitHistory:
    """One conventional repository, held under the parent workspace lease."""
    def __init__(self, workspace, directory, sandbox, *, nested=False, snapshot_budget=None):
        from agentporter.sandbox.git_snapshot import SnapshotBudget
        self.snapshot_budget = snapshot_budget if snapshot_budget is not None else SnapshotBudget()
        self.workspace = Path(workspace).resolve(strict=True)
        self.sandbox = sandbox
        self.mount = None
        self._lease = None
        self.guard = None
        self.changed = False
        self.approved_pull = None
        self._pull_intent = None
        if nested:
            self._lease = mutation_lease(self.workspace, sandbox.state_dir / 'workspace-transactions')
            self._lease.__enter__()
        try:
            result = sandbox._run_command(workspace_path=str(self.workspace),
                argv=['/usr/bin/python3', '-I', '-S', '-c', _HISTORY_INSPECT], writable=False,
                network_access=False, timeout_seconds=20, max_output_bytes=65536,
                require_resources=True)
            if result['exit_code']:
                raise PermissionError('Cannot inspect private Git snapshot baseline')
            self.before = json.loads(result['stdout'])
            identity = self.workspace.stat()
            request = {'repository_path': str(self.workspace),
                'repository_device': identity.st_dev, 'repository_inode': identity.st_ino,
                'expected_tree': self.before['tree']}
            self.mount = _MetadataMount(request, source_objects=True)
            directory.mkdir(mode=0o700)
            snapshot_plan = self.snapshot_budget.preflight(self.mount.git, directory)
            from agentporter.sandbox.workspace_git_recovery import capture_git_baseline
            self.raw_baseline_directory=directory/'raw-before'
            self.raw_baseline=capture_git_baseline(f'/proc/self/fd/{self.mount.root}/.',self.raw_baseline_directory,
                                                 copy_guard=self.snapshot_budget.guard_raw_write)
            self.native_events=directory/'native-events'
            self.native_events.mkdir(mode=0o700)
            self.private = directory / 'metadata'
            self.shared_sources = _copy_directory(self.mount.git, self.private, self.snapshot_budget, preflight=snapshot_plan)
            self.clean_config = directory / 'clean-config'
            os.lseek(self.mount.config, 0, os.SEEK_SET)
            config = os.read(self.mount.config, 8192)
            self.clean_config.write_bytes(config + b'[user]\nname = AgentPorter\nemail = agents@agentporter.invalid\n')
            (self.private / 'config').write_bytes(self.clean_config.read_bytes())
            # Host hooks and linked-worktree administration are not history.
            import shutil
            for name in ('hooks', 'worktrees'):
                path = self.private / name
                if path.is_dir():
                    shutil.rmtree(path)
                elif path.exists():
                    path.unlink()
            if self.shared_sources:
                self._validate_shared_objects()
            _reject_excluded_git_paths(self.private, self.workspace)
            self.exchange = directory / 'exchange'
            self.exchange.mkdir(mode=0o700)
        except BaseException:
            self.close()
            raise

    def _validate_shared_objects(self):
        self.snapshot_budget.check()
        result = self.sandbox._run_command(workspace_path=str(self.workspace),
            argv=['/usr/bin/python3', '-I', '-S', '-c', _VALIDATE_SHARED_OBJECTS,
                  json.dumps(sorted(self.shared_sources)), str(len(self.before['tree']))],
            writable=False, network_access=False, timeout_seconds=max(1, min(20,
                int(self.snapshot_budget.deadline - time.monotonic()))), max_output_bytes=4096,
            workspace_transaction=_PrivateMount(self), require_resources=True)
        self.snapshot_budget.check()
        if result['exit_code'] or result['stdout'].strip() != 'SHARED_GIT_OBJECTS_VERIFIED':
            raise PermissionError('Shared Git source object integrity validation failed')
        self._check_shared_sources()

    def _check_shared_sources(self):
        from agentporter.sandbox.git_snapshot import FLAGS, signature
        for path, record in self.shared_sources.items():
            parent = os.dup(self.mount.git)
            try:
                for name in path.split('/')[:-1]:
                    child = os.open(name, FLAGS, dir_fd=parent)
                    os.close(parent); parent = child
                if signature(os.stat(path.split('/')[-1], dir_fd=parent, follow_symlinks=False)) != tuple(record['signature']):
                    raise PermissionError('Shared canonical object changed; owner state retained')
            finally:
                os.close(parent)

    def attach_approved_pull(self, intent):
        from agentporter.git_pulls import _PullPublicationIntent
        if (not isinstance(intent, _PullPublicationIntent)
                or intent.transaction.git_histories.get('.git' if intent.request.to_payload()['parameters'].get('repository_relative','.')=='.' else intent.request.to_payload()['parameters']['repository_relative']+'/.git') is not self
                or getattr(intent.transaction, '_pull_publication_intent', None) is not intent):
            raise PermissionError('Git history requires its exact native consumed pull intent')
        intent.validate()
        self._pull_intent = intent
        self.approved_pull = intent.to_payload()

    def prepare(self):
        from agentporter.sandbox.workspace_git_recovery import _digest
        approved_paths = ()
        if self._pull_intent is not None:
            approved_paths = self._pull_intent.validate()
            if self.approved_pull != self._pull_intent.to_payload():
                raise PermissionError('Pull history authorization changed')
        # No worker process may still be running when this method is called.
        self._check_shared_sources()
        _reject_excluded_git_paths(self.private, self.workspace)
        fd = os.open(self.private, _FLAGS)
        try:
            _inspect_metadata(fd, _mount_id(fd))
        finally:
            os.close(fd)
        result = self.sandbox._run_command(workspace_path=str(self.workspace),
            argv=['/usr/bin/python3', '-I', '-S', '-c', _EXPORT,
                  json.dumps(self.before), _HISTORY_INSPECT, json.dumps(self.approved_pull)], writable=False,
            network_access=False, timeout_seconds=30, max_output_bytes=65536,
            workspace_transaction=_PrivateMount(self, exchange=True), require_resources=True)
        if result['exit_code']:
            raise PermissionError('Private Git history validation failed')
        after = json.loads(result['stdout'])
        self.changed = after != self.before or self.approved_pull is not None
        self.plan = {'before': self.before, 'after': after,'publication_time':int(time.time())}
        if self.approved_pull is not None:
            self.plan['approved_pull'] = self.approved_pull
        if self.changed:
            from agentporter.sandbox.native_git_provenance import build
            self.provenance_build=build(self.native_events.parent)
            self.plan['native_bridge']=self.provenance_build
            self.guard = self.sandbox.state_dir / 'workspace-transactions' / (
                workspace_key(os.fstat(self.mount.root)) + '.git-pending.json')
            from agentporter.sandbox.native_git_cleanup import preflight
            self.native_guard_directory=self.native_events.parent/'native-guard-retire'
            preflight(f'/proc/self/fd/{self.mount.root}/.',self.native_guard_directory,
                      self.raw_baseline['manifest'],self.plan)
            from agentporter.sandbox.git_original_metadata import prepare
            self.original_directory=self.native_events.parent/'preserved-metadata'
            self.original_plan=prepare(f'/proc/self/fd/{self.mount.root}/.',self.raw_baseline_directory,
                                      self.raw_baseline['sha256'],self.original_directory,
                                      **({'approved_paths': approved_paths, 'approval_sha256':
                                          _digest(self.approved_pull['authorization'])}
                                         if self.approved_pull is not None else {}))

    def guard_publication(self):
        self._check_shared_sources()
        if not self.changed:
            return
        from agentporter.sandbox.workspace_git_recovery import verify_git_baseline
        verify_git_baseline(f'/proc/self/fd/{self.mount.root}/.',self.raw_baseline_directory,self.raw_baseline['sha256'])
        if self._pull_intent is not None:
            self._pull_intent.validate()
            from agentporter.sandbox.workspace_custody import capture_workspace_entry
            captured = capture_workspace_entry(self._pull_intent.guard.parent, self._pull_intent.guard.name,
                Path(self.approved_pull['consumed_guard_custody']),
                expected_record=self.approved_pull['consumed_guard_record'])
            if not captured['expected'] or captured['state'] != 'captured_expected':
                raise ResourceCleanupError('Consumed pull guard migration requires owner recovery')
        with open(self.guard, 'x', encoding='utf-8') as output:
            os.chmod(self.guard, 0o600)
            from agentporter.sandbox.workspace_git_recovery import _digest
            json.dump({'version': 7 if self.approved_pull is not None else 6, 'workspace': str(self.workspace),
                       'plan': self.plan, 'exchange': str(self.exchange),
                       'raw_baseline':{'directory':str(self.raw_baseline_directory),
                                       'sha256':self.raw_baseline['sha256']},
                       'native_journal':str(self.native_events),
                       'original_metadata':{'directory':str(self.original_directory),
                                            'sha256':_digest(self.original_plan)}}, output, sort_keys=True)
            output.flush()
            os.fsync(output.fileno())
            guard_signature=list(_guard_signature(os.fstat(output.fileno())))
        fd = os.open(self.guard.parent, _FLAGS)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)

        from agentporter.sandbox.workspace_delta import backup_workspace_deletion
        self.guard_record=backup_workspace_deletion(self.guard.parent,self.guard.name,
            self.raw_baseline_directory/'git-guard.backup',expected_signature=guard_signature)
        from agentporter.sandbox.workspace_git_recovery import record_git_phase
        record_git_phase(f'/proc/self/fd/{self.mount.root}/.',self.raw_baseline_directory,'guarded',
            {'guard_sha256':self.guard_record['sha256'],
             'baseline_sha256':self.raw_baseline['sha256'],
             'guard_record':self.guard_record})

    def publish(self):
        self._check_shared_sources()
        if self._pull_intent is not None:
            self._pull_intent.validate(migrated=True)
        _reject_excluded_git_paths(self.private, self.workspace)
        if not self.changed:
            return
        from agentporter.sandbox.workspace_git_recovery import record_git_phase, inspect_git_phases, capture_git_baseline, verify_git_baseline
        source=f'/proc/self/fd/{self.mount.root}/.'
        phases=inspect_git_phases(source,self.raw_baseline_directory)
        if not phases['events'] or phases['events'][-1]['phase']!='guarded':
            raise ResourceCleanupError('Git import has prior uncertain lifecycle evidence; inspect recovery')
        binding=phases['events'][0]['payload']
        from agentporter.sandbox.workspace_delta import _read_deletion_file
        try:
            descriptor=os.open(self.guard,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
            try:_read_deletion_file(descriptor,expected_signature=self.guard_record['signature'],
                                   expected_sha256=self.guard_record['sha256'])
            finally:os.close(descriptor)
        except (OSError,PermissionError) as error:
            raise ResourceCleanupError('Git guard identity changed; inspected recovery required') from error
        if (binding.get('baseline_sha256')!=self.raw_baseline['sha256']
                or binding.get('guard_sha256')!=self.guard_record['sha256']):
            raise ResourceCleanupError('Git import guard or baseline binding changed')
        try:verify_git_baseline(source,self.raw_baseline_directory,self.raw_baseline['sha256'])
        except (OSError,PermissionError) as error:
            raise ResourceCleanupError('Raw Git baseline changed; inspected recovery required') from error
        from agentporter.sandbox.git_original_metadata import publish_before_copy
        native_before={}
        for path in sorted(self.original_plan['entries']):
            native_before[path]=publish_before_copy(source,self.original_directory,path)
        from agentporter.sandbox.git_original_metadata import _write
        _write(self.native_events,'native-before.json',native_before)
        record_git_phase(source,self.raw_baseline_directory,'import_started',{'plan':self.plan})
        result = self.sandbox._run_command(workspace_path=str(self.workspace),
            argv=['/usr/bin/python3', '-I', '-S', '-c', _IMPORT,
                  json.dumps(self.plan), _HISTORY_INSPECT, '/git-publication'], writable=False,
            git_metadata_writable=True, network_access=False,
            timeout_seconds=60, max_output_bytes=8192,
            workspace_transaction=_ImportMount(self), require_resources=True)
        from agentporter.sandbox.workspace_git_recovery import inspect_native_git_phases, _digest
        native=inspect_native_git_phases(source,self.native_events,_digest(self.plan))
        after=None;cleanup_sha256=None
        if not result['exit_code'] and result['stdout'].strip()=='WORKSPACE_GIT_IMPORTED':
            from agentporter.sandbox.native_git_cleanup import retire
            try:cleanup_sha256=retire(source,self.native_guard_directory,self.plan,native)
            except (OSError,PermissionError) as error:
                raise ResourceCleanupError('Native guard retirement requires owner recovery; custody retained') from error
            after=capture_git_baseline(source,self.raw_baseline_directory.parent/'raw-after')['sha256']
        record_git_phase(source,self.raw_baseline_directory,'import_returned',
            {'exit_code':result['exit_code'],'after_sha256':after,
             'native_events_sha256':native['sha256'],'native_guard_cleanup_sha256':cleanup_sha256})
        if result['exit_code'] or result['stdout'].strip() != 'WORKSPACE_GIT_IMPORTED':
            raise ResourceCleanupError('Local Git import requires owner recovery; guard retained')

    def finish(self):
        if self.changed:
            from agentporter.sandbox.workspace_custody import capture_workspace_entry
            parent=self.guard.parent.parent/'git-guard-custody'
            parent.mkdir(mode=0o700,exist_ok=True)
            operation=parent/(self.raw_baseline_directory.parent.parent.name+'-'+self.raw_baseline_directory.parent.name)
            result=capture_workspace_entry(self.guard.parent,self.guard.name,operation,expected_record=self.guard_record)
            if not result['expected'] or result['state']!='captured_expected':
                raise ResourceCleanupError('Git guard retirement conflicts with owner work; custody retained')

    def close(self):
        if self.mount is not None:
            self.mount.close()
            self.mount = None
        if self._lease is not None:
            self._lease.__exit__(None, None, None)
            self._lease = None
