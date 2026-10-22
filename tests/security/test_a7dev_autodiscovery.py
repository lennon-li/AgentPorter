"""Synthetic acceptance tests: never touch the installed service/configuration."""
import importlib.util
import os
import pwd
from pathlib import Path
import sqlite3
import subprocess
import yaml
import pytest

try:
    SERVICE_UID = pwd.getpwnam('agentporter-dev').pw_uid
except KeyError:
    SERVICE_UID = 12345
if SERVICE_UID == os.getuid():
    SERVICE_UID += 1

SCRIPT = Path(__file__).resolve().parents[2] / 'scripts/autodiscover-a7dev.py'
spec = importlib.util.spec_from_file_location('autodiscovery', SCRIPT)
a = importlib.util.module_from_spec(spec)
spec.loader.exec_module(a)


def documents():
    return {'workspaces.yaml': {'workspaces': {'explicit': {'path': '/existing', 'writable': False}}},
            'public-client-policy.yaml': {'version': 1, 'workspaces': {'explicit': {'path': '/existing', 'operations': ['read']}}},
            'development-runtime.yaml': {'allowed_workspace_roots': [{'path': '/existing', 'writable': False}], 'workers': {'keep': {'model': 'unchanged'}}}}


def test_defaults_explicit_preservation_and_noop():
    docs = documents()
    output, state, report = a.plan(docs, {}, {'demo': {'path': '/repos/demo', 'dev': 1, 'ino': 3}})
    assert output['workspaces.yaml']['workspaces']['explicit'] == docs['workspaces.yaml']['workspaces']['explicit']
    row = output['workspaces.yaml']['workspaces']['demo']
    assert all(row[k] for k in ('writable', 'allow_execute', 'allow_git', 'allow_artifacts', 'allow_agent_dispatch'))
    assert row['local_http_ports'] == []
    assert not any(row[k] for k in ('allow_venkata_ssh', 'allow_venkata_transfer', 'allow_scinet_training', 'allow_scinet_diagnostic'))
    assert output['public-client-policy.yaml']['workspaces']['demo']['operations'] == ['read', 'write', 'git_read', 'exec', 'dispatch']
    assert output['development-runtime.yaml']['allowed_workspace_roots'][-1] == {'path': '/repos/demo', 'writable': False}
    assert output['development-runtime.yaml']['workers'] == docs['development-runtime.yaml']['workers']
    assert a.plan(output, state, {'demo': {'path': '/repos/demo', 'dev': 1, 'ino': 3}})[0] == output
    assert a.plan(output, state, {})[0] == docs


def test_capacity_and_override():
    docs = documents()
    docs['development-runtime.yaml']['allowed_workspace_roots'] *= 64
    # Duplicate roots fail closed, even before capacity planning.
    with pytest.raises(ValueError):
        a.plan(docs, {}, {})
    docs['development-runtime.yaml']['allowed_workspace_roots'] = [{'path': f'/old/{n}', 'writable': False} for n in range(64)]
    out, state, report = a.plan(docs, {}, {'demo': {'path': '/repos/demo', 'dev': 1, 'ino': 1}})
    assert out == docs and report['pending'] == ['demo'] and state == {}
    out, state, _ = a.plan(documents(), {}, {'demo': {'path': '/repos/demo', 'dev': 1, 'ino': 1}})
    out['workspaces.yaml']['workspaces']['demo']['writable'] = False
    again, managed, report = a.plan(out, state, {})
    assert again == out and managed == {} and report['overridden'] == ['demo']


def test_candidate_filtering_and_pinning(tmp_path):
    for name in ('good', 'obsidian', 'AgentPorter', '.hidden', 'bad name', 'runtime', 'foo.pem'):
        (tmp_path / name).mkdir()
    (tmp_path / 'alias').symlink_to(tmp_path / 'good', target_is_directory=True)
    with a.directory(tmp_path) as fd:
        roots = a.discover(fd, str(tmp_path), os.getuid())
        assert set(roots) == {'good'}
        root = roots['good']
        (tmp_path / 'good').rename(tmp_path / 'renamed')
        (tmp_path / 'good').mkdir()
        with pytest.raises(ValueError):
            a.pin_candidate(fd, 'good', root, os.getuid())
        assert a.discover(fd, str(tmp_path), os.getuid() + 1) == {}


@pytest.mark.parametrize('body', [b'x: 1\nx: 2', b'x: &x [1]\ny: *x', b'x: !!python/object:bad {}', b'x: {1: 2}'])
def test_strict_yaml(body):
    with pytest.raises((ValueError, yaml.YAMLError)):
        a.load_yaml(body)


def test_private_reads(tmp_path):
    (tmp_path / 'ok').write_bytes(b'hello')
    os.chmod(tmp_path / 'ok', 0o600)
    with a.directory(tmp_path) as fd:
        assert a.private_read(fd, 'ok', os.getuid()) == b'hello'
        (tmp_path / 'link').symlink_to(tmp_path / 'ok')
        with pytest.raises(OSError):
            a.private_read(fd, 'link', os.getuid())
        os.link(tmp_path / 'ok', tmp_path / 'hard')
        with pytest.raises(ValueError):
            a.private_read(fd, 'ok', os.getuid())


def test_admission_write_barrier(tmp_path):
    dbpath = tmp_path / 'jobs.db'
    with sqlite3.connect(dbpath) as db:
        db.execute('create table jobs(status text)')
        db.execute('create table job_admissions(id text)')
    with a.admission_transaction(str(dbpath)):
        with sqlite3.connect(dbpath, timeout=0) as contender:
            with pytest.raises(sqlite3.OperationalError, match='locked'):
                contender.execute("insert into job_admissions values ('new')")
    with sqlite3.connect(dbpath) as db:
        db.execute("insert into jobs values ('cleanup_failed')")
    with pytest.raises(a.Busy):
        with a.admission_transaction(str(dbpath)):
            pass


def test_acl_native_private_git_hardlink_and_symlink(tmp_path):
    uid = os.getuid()
    # A numeric ACL for an unrelated UID can be set on our own temporary files.
    recipient = SERVICE_UID
    project = tmp_path / 'project'
    project.mkdir()
    (project / 'normal').write_text('public')
    (project / '.env').write_text('private')
    (project / '.git').mkdir()
    (project / '.git/config').write_text('git')
    (project / '.ssh').mkdir()
    (project / '.ssh/key').write_text('private')
    outside = tmp_path / 'outside'
    outside.write_text('untouched')
    os.link(outside, project / 'hard')
    (project / 'sym').symlink_to(outside)
    before = subprocess.check_output(['/usr/bin/getfacl', '-cp', str(outside)])
    with a.directory(project) as fd:
        a.grant_tree(fd, uid, recipient)
    acl = lambda p: subprocess.check_output(['/usr/bin/getfacl', '-cpn', str(p)], text=True)
    assert f'user:{recipient}:rw-' in acl(project / 'normal')
    assert f'user:{recipient}:---' in acl(project / '.env')
    assert f'user:{recipient}:r-x' in acl(project / '.git')
    assert f'user:{recipient}:r--' in acl(project / '.git/config')
    assert f'user:{recipient}:---' in acl(project / '.ssh')
    assert subprocess.check_output(['/usr/bin/getfacl', '-cp', str(outside)]) == before
    assert f'default:user:{recipient}:---' in acl(project)


def test_acl_mask_preserves_unrelated_effective_rights(tmp_path):
    file = tmp_path / 'file'
    file.write_text('x')
    # Only own UID/GID is mapped in some Codex sandboxes.
    subprocess.run(['setfacl', '-m', f'g:{os.getgid()}:rwx,m::r--', str(file)], check=True)
    with a.directory(tmp_path) as fd:
        f = os.open('file', os.O_RDONLY, dir_fd=fd)
        try:
            a.set_acl(f, os.getuid(), 'rw-')
        finally:
            os.close(f)
    acl = subprocess.check_output(['getfacl', '-cpn', str(file)], text=True)
    assert f'group:{os.getgid()}:r--' in acl


def control_fixture(tmp_path):
    config, state = tmp_path / 'config', tmp_path / 'state'
    config.mkdir()
    state.mkdir()
    before = {n: yaml.safe_dump(d).encode() for n, d in documents().items()}
    after = {n: body + b'\n# new\n' for n, body in before.items()}
    for n, body in before.items():
        (config / n).write_bytes(body)
        os.chmod(config / n, 0o600)
    return config, state, before, after


@pytest.mark.parametrize('failure', ['write', 'start', 'health'])
def test_transaction_failure_exact_rollback(tmp_path, monkeypatch, failure):
    config, state, before, after = control_fixture(tmp_path)
    calls = []
    uid = os.getuid()
    realwrite = a.atomic_write
    failed = [False]
    def write(fd, name, body, owner):
        if failure == 'write' and name == a.FILES[1] and body == after[name] and not failed[0]:
            failed[0] = True
            raise OSError('injected write')
        return realwrite(fd, name, body, uid)  # root-private fixture owned by us
    def system(*args, **kwargs):
        calls.append(args[0])
        if failure == 'start' and args[0] == 'start' and not failed[0]:
            failed[0] = True
            raise OSError('injected start')
        return subprocess.CompletedProcess(args, 3 if args[0] == 'is-active' else 0)
    def health():
        if failure == 'health' and not failed[0]:
            failed[0] = True
            raise OSError('injected health')
    monkeypatch.setattr(a, 'atomic_write', write)
    monkeypatch.setattr(a, 'systemctl', system)
    monkeypatch.setattr(a, 'health', health)
    monkeypatch.setattr(a, 'read_state', lambda fd: ({}, b'{}'))
    realread = a.private_read
    monkeypatch.setattr(a, 'private_read', lambda fd, name, owner, **kw: realread(fd, name, uid, **kw))
    with a.directory(config) as cfd, a.directory(state) as sfd:
        with pytest.raises(OSError, match='injected'):
            a.transaction(cfd, sfd, uid, before, after, b'{}', b'{"new":1}')
    assert all((config / n).read_bytes() == b for n, b in before.items())
    assert calls[-1] == 'start'


def test_recovery_partial_and_unknown_refusal(tmp_path, monkeypatch):
    config, state, before, after = control_fixture(tmp_path)
    receipt = {'version': 1, 'before': {n: a.encode(b) for n, b in before.items()},
               'after': {n: a.encode(b) for n, b in after.items()}, 'state_before': a.encode(b'{}'),
               'state_after': a.encode(b'{"new":1}'), 'was_active': False, 'phase': 'prepared'}
    uid = os.getuid()
    realwrite = a.atomic_write
    monkeypatch.setattr(a, 'atomic_write', lambda fd, name, body, owner: realwrite(fd, name, body, uid))
    monkeypatch.setattr(a, 'read_state', lambda fd: ({}, b'{}'))
    (config / a.FILES[0]).write_bytes(after[a.FILES[0]])
    with a.directory(config) as cfd, a.directory(state) as sfd:
        a.recover(cfd, sfd, uid, receipt)
        assert all((config / n).read_bytes() == b for n, b in before.items())
        (config / a.FILES[0]).write_bytes(b'unknown editor bytes')
        with pytest.raises(ValueError, match='Unknown/newer'):
            a.recover(cfd, sfd, uid, receipt)
        assert (config / a.FILES[0]).read_bytes() == b'unknown editor bytes'


def test_durable_guards_allow_empty_startup_but_deny_admission(tmp_path):
    path = tmp_path / 'jobs.db'
    with sqlite3.connect(path) as db:
        db.execute('create table jobs(status text)')
        db.execute('create table job_admissions(id text)')
    token = 'a' * 32
    a.install_guards(str(path), token)
    # Mirrors JobManager._init_db's unconditional, empty INSERT SELECT.
    with sqlite3.connect(path) as db:
        db.execute("insert or ignore into job_admissions select status from jobs where status='running'")
        with pytest.raises(sqlite3.IntegrityError, match='A7Dev reconciliation'):
            db.execute("insert into job_admissions values ('new')")
    # A crash loses the helper process, not the committed guard.
    a.install_guards(str(path), token)
    with pytest.raises(ValueError, match='Unknown admission guard'):
        a.install_guards(str(path), 'b' * 32)
    a.release_guards(str(path), token)
    with sqlite3.connect(path) as db:
        db.execute("insert into job_admissions values ('new')")
    with pytest.raises(a.Busy):
        a.install_guards(str(path), token)


def test_unknown_guard_not_overwritten(tmp_path):
    path = tmp_path / 'jobs.db'
    with sqlite3.connect(path) as db:
        db.execute('create table jobs(status text)')
        db.execute('create table job_admissions(id text)')
        db.execute('create trigger a7dev_autodiscovery_guard_insert before insert on job_admissions begin select 1; end')
    with pytest.raises(ValueError, match='Unknown admission guard'):
        a.install_guards(str(path), 'a' * 32)
    with sqlite3.connect(path) as db:
        assert db.execute("select sql from sqlite_master where type='trigger'").fetchone()[0].endswith('select 1; end')


def test_explicit_root_overlap_and_umbrella_exception():
    docs = documents()
    docs['workspaces.yaml']['workspaces']['nested'] = {'path': '/repos/new/protected', 'writable': False}
    candidates = {'new': {'path': '/repos/new', 'dev': 1, 'ino': 1},
                  'inside': {'path': '/existing/inside', 'dev': 1, 'ino': 2}}
    result, managed, report = a.plan(docs, {}, candidates)
    assert result == docs and managed == {} and report['overlaps'] == ['inside', 'new']
    docs = documents()
    docs['workspaces.yaml']['workspaces']['repos'] = {'path': a.REPOS, 'writable': False}
    identity = {'path': a.REPOS + '/new', 'dev': 1, 'ino': 1}
    assert a.plan(docs, {}, {'new': identity})[2]['added'] == ['new']


def test_special_entries_never_opened_for_data(tmp_path, monkeypatch):
    os.mkfifo(tmp_path / 'fifo')
    calls = []
    monkeypatch.setattr(a, 'set_acl', lambda fd, *args, **kwargs: calls.append(os.fstat(fd).st_mode))
    with a.directory(tmp_path) as fd:
        a.grant_tree(fd, os.getuid(), os.getuid() + 12345)
    assert len(calls) == 1  # Root only; O_PATH does not activate the FIFO.


def run_fixture(tmp_path, monkeypatch, busy=False):
    config, state, before, _ = control_fixture(tmp_path)
    repos = tmp_path / 'repos'
    repos.mkdir()
    (repos / 'new').mkdir()
    with a.directory(repos) as fd:
        candidates = a.discover(fd, str(repos), os.getuid())
    result, managed, _ = a.plan(documents(), {}, candidates)
    for name, doc in result.items():
        (config / name).write_text(yaml.safe_dump(doc))
    (state / 'managed.json').write_bytes(a.canonical(managed))
    os.chmod(state / 'managed.json', 0o600)
    for key, value in [('CONFIG', config), ('STATE', state), ('REPOS', str(repos))]:
        monkeypatch.setattr(a, key, str(value))
    monkeypatch.setattr(a, 'installed_identity', lambda: None)
    monkeypatch.setattr(a.os, 'geteuid', lambda: 0)
    class Account:
        pw_uid = os.getuid()
    monkeypatch.setattr(a.pwd, 'getpwnam', lambda _: Account())
    original_metadata = a.metadata
    monkeypatch.setattr(a, 'metadata', lambda fd, uid, mode=None: original_metadata(fd, os.getuid(), None))
    original_read = a.private_read
    monkeypatch.setattr(a, 'private_read', lambda fd, name, uid, **kw: original_read(fd, name, os.getuid(), **kw))
    import contextlib
    @contextlib.contextmanager
    def barrier(fd):
        if busy:
            raise a.Busy('fixture busy')
        yield object()
    monkeypatch.setattr(a, 'barrier', barrier)
    monkeypatch.setattr(a, 'verify_barrier', lambda _: None)
    monkeypatch.setattr(a, 'grant_tree', lambda *args, **kwargs: None)
    service_calls = []
    monkeypatch.setattr(a, 'systemctl', lambda *args, **kwargs: service_calls.append(args))
    return service_calls, config


def test_noop_scan_never_stops_or_restarts(tmp_path, monkeypatch):
    service_calls, _ = run_fixture(tmp_path, monkeypatch)
    report = a.run(True)
    assert not report['configuration_changed'] and not service_calls


def test_busy_scan_never_stops_or_changes_config(tmp_path, monkeypatch):
    service_calls, config = run_fixture(tmp_path, monkeypatch, busy=True)
    before = {p.name: p.read_bytes() for p in config.iterdir()}
    with pytest.raises(a.Busy):
        a.run(True)
    assert not service_calls
    assert before == {p.name: p.read_bytes() for p in config.iterdir()}


def test_oversized_acl_scan_defers_without_restart(tmp_path, monkeypatch):
    service_calls, config = run_fixture(tmp_path, monkeypatch)
    before = {p.name: p.read_bytes() for p in config.iterdir()}
    def oversized(*args, **kwargs):
        raise ValueError('ACL traversal bound exceeded; candidate deferred')
    monkeypatch.setattr(a, 'grant_tree', oversized)
    result = a.run(True)
    assert result['deferred_acl']['workspace'] == 'new'
    assert not result['configuration_changed'] and not service_calls
    assert before == {p.name: p.read_bytes() for p in config.iterdir()}


def test_owner_swaps_and_mount_boundaries(tmp_path, monkeypatch):
    (tmp_path / 'new').mkdir()
    with a.directory(tmp_path) as fd:
        original_mount = a.mount_id
        # Simulate same-device bind mount without touching host mount state.
        monkeypatch.setattr(a, 'mount_id', lambda f: original_mount(f) if f == fd else original_mount(f) + 1)
        assert not a.discover(fd, str(tmp_path), os.getuid())
        monkeypatch.setattr(a, 'mount_id', original_mount)
        candidate = a.discover(fd, str(tmp_path), os.getuid())['new']
        with pytest.raises(ValueError, match='owner changed'):
            a.pin_candidate(fd, 'new', candidate, os.getuid() + 1)


def test_update_guard_remains_after_helper_disappears(tmp_path):
    path = tmp_path / 'jobs.db'
    with sqlite3.connect(path) as db:
        db.execute('create table jobs(status text)')
        db.execute('create table job_admissions(id text)')
    token = 'c' * 32
    a.install_guards(str(path), token)
    with sqlite3.connect(path) as db:
        # To exercise UPDATE, seed a row with INSERT guard temporarily removed
        # within one transaction, then restore exact static guard immediately.
        db.execute('DROP TRIGGER a7dev_autodiscovery_guard_insert')
        db.execute("insert into job_admissions values ('already')")
        db.execute(a.guard_sql(token)['a7dev_autodiscovery_guard_insert'])
        with pytest.raises(sqlite3.IntegrityError, match='A7Dev reconciliation'):
            db.execute("update job_admissions set id='new'")
        with pytest.raises(a.Busy):
            a.release_guards(str(path), token)


@pytest.mark.parametrize('kind', ['child', 'ancestor', 'alias'])
def test_new_explicit_overlap_revokes_managed_root(kind):
    identity = {'path': '/repos/new', 'dev': 1, 'ino': 1}
    docs, state, _ = a.plan(documents(), {}, {'new': identity})
    path = {'child': '/repos/new/restricted', 'ancestor': '/repos', 'alias': '/repos/new'}[kind]
    restricted = {'path': path, 'writable': False, 'allow_execute': False, 'allow_agent_dispatch': False}
    docs[a.FILES[0]]['workspaces']['restricted'] = restricted.copy()
    docs[a.FILES[1]]['workspaces']['restricted'] = {'path': path, 'operations': ['read']}
    output, managed, report = a.plan(docs, state, {'new': identity})
    assert not managed and 'new' not in output[a.FILES[0]]['workspaces']
    assert 'new' not in output[a.FILES[1]]['workspaces']
    assert output[a.FILES[0]]['workspaces']['restricted'] == restricted
    assert report['revoked'] == ['new']
    if kind != 'alias':
        assert {'path': identity['path'], 'writable': False} not in output[a.FILES[2]]['allowed_workspace_roots']


def test_revoked_managed_root_is_not_acl_refreshed(tmp_path, monkeypatch):
    service_calls, config = run_fixture(tmp_path, monkeypatch)
    registry = yaml.safe_load((config / a.FILES[0]).read_bytes())
    root = registry['workspaces']['new']['path']
    registry['workspaces']['restricted'] = {'path': root + '/restricted', 'writable': False}
    (config / a.FILES[0]).write_text(yaml.safe_dump(registry))
    grants = []
    monkeypatch.setattr(a, 'grant_tree', lambda *args, **kwargs: grants.append(args))
    monkeypatch.setattr(a, 'systemctl', lambda *args, **kwargs: subprocess.CompletedProcess(args, 0))
    transactions = []
    monkeypatch.setattr(a, 'transaction', lambda *args, **kwargs: transactions.append(args))
    result = a.run(True)
    assert result['revoked'] == ['new'] and not grants and len(transactions) == 1


def test_samepath_alias_enforces_real_launcher_and_public_policy(tmp_path):
    # These deployment-overlay modules are absent from the generic package.
    development = pytest.importorskip('agentporter.agents.development')
    policy = pytest.importorskip('agentporter.client_policy')
    DevelopmentRuntime = development.DevelopmentRuntime
    PublicClientPolicy, PRINCIPAL = policy.PublicClientPolicy, policy.PRINCIPAL
    from agentporter.workspaces.registry import WorkspaceRegistry
    root, base = tmp_path / 'new', tmp_path / 'base'
    root.mkdir()
    base.mkdir()
    docs = documents()
    for name in a.FILES[:2]:
        docs[name]['workspaces']['explicit']['path'] = str(base)
    docs[a.FILES[2]]['allowed_workspace_roots'][0]['path'] = str(base)
    identity = {'path': str(root), 'dev': root.stat().st_dev, 'ino': root.stat().st_ino}
    enrolled, managed, _ = a.plan(docs, {}, {'new': identity})
    enrolled[a.FILES[0]]['workspaces']['restricted'] = {'path': str(root), 'writable': False,
        'allow_execute': False, 'allow_agent_dispatch': False}
    enrolled[a.FILES[1]]['workspaces']['restricted'] = {'path': str(root), 'operations': ['read']}
    output, managed, _ = a.plan(enrolled, managed, {'new': identity})
    registry = WorkspaceRegistry(output[a.FILES[0]]['workspaces'])
    runtime = DevelopmentRuntime.__new__(DevelopmentRuntime)
    runtime.workspace_registry = registry
    with pytest.raises(PermissionError, match='not authorized'):
        runtime._workspace(str(root), False, output[a.FILES[2]])
    config, state = tmp_path / 'config', tmp_path / 'state'
    config.mkdir()
    state.mkdir()
    (config / a.FILES[1]).write_text(yaml.safe_dump(output[a.FILES[1]]))
    os.chmod(config / a.FILES[1], 0o600)
    policy = PublicClientPolicy(config, state, registry, required=True)
    token = PRINCIPAL.set('public')
    try:
        policy.check('workspace_info', {'workspace_id': 'restricted'})
        for name in ('restricted', 'new'):
            with pytest.raises(PermissionError):
                policy.check('dispatch_agent', {'workspace_id': name})
    finally:
        PRINCIPAL.reset(token)


@pytest.mark.parametrize('name', ['id_rsa', 'ID_ED25519', '.ENV', '.envPrivate', 'key.PEM', 'KEY.Key',
                                  'AUTH.JSON', 'Credentials.Json', 'Secrets.Env', '.BASHRC', '.Git-Credentials'])
def test_private_classes_case_insensitive_denied(tmp_path, name):
    file = tmp_path / name
    file.write_text('synthetic private fixture')
    os.chmod(file, 0o600)
    recipient = SERVICE_UID
    with a.directory(tmp_path) as fd:
        a.grant_tree(fd, os.getuid(), recipient)
    acl = subprocess.check_output(['getfacl', '-cpn', str(file)], text=True)
    assert f'user:{recipient}:---' in acl


def test_private_credential_directories_not_traversed(tmp_path):
    recipient = SERVICE_UID
    for name in ('.gnupg', '.CONFIG', '.cache', '.AWS', '.SSH'):
        directory = tmp_path / name
        directory.mkdir()
        (directory / 'private').write_text('synthetic fixture')
    with a.directory(tmp_path) as fd:
        a.grant_tree(fd, os.getuid(), recipient)
    for path in tmp_path.iterdir():
        acl = subprocess.check_output(['getfacl', '-cpn', str(path)], text=True)
        inner = subprocess.check_output(['getfacl', '-cpn', str(path / 'private')], text=True)
        assert f'user:{recipient}:---' in acl
        assert f'user:{recipient}:' not in inner


def test_installer_pins_reviewed_installable_bytes():
    import hashlib
    import re
    scripts = SCRIPT.parent
    installer = (scripts / 'install-a7dev-autodiscovery.sh').read_text()
    for key, name in [('helper_sha', 'autodiscover-a7dev.py'),
                      ('service_sha', 'agentporter-dev-autodiscovery.service'),
                      ('timer_sha', 'agentporter-dev-autodiscovery.timer'),
                      ('repair_sha', 'install-a7dev-acquisition-repair.sh')]:
        expected = re.search(r'readonly ' + key + r'=([0-9a-f]{64})', installer).group(1)
        assert hashlib.sha256((scripts / name).read_bytes()).hexdigest() == expected, name
    reload = installer.index('sudo /usr/bin/systemctl daemon-reload')
    first_run = installer.index('sudo /usr/bin/systemctl start agentporter-dev-autodiscovery.service')
    timer = installer.index('sudo /usr/bin/systemctl enable --now agentporter-dev-autodiscovery.timer')
    assert reload < first_run < timer


def test_installed_location_avoids_private_libexec_ancestor():
    import stat
    assert a.INSTALLED == '/opt/agentporter-autodiscovery/autodiscover-a7dev.py'
    installer = (SCRIPT.parent / 'install-a7dev-autodiscovery.sh').read_text()
    assert 'readonly target=/opt/agentporter-autodiscovery' in installer
    assert 'sudo /usr/bin/install -d -o root -g root -m 0755 "$target"' in installer
    assert 'sudo /usr/bin/install -T -o root -g root -m 0644 /dev/stdin "$destination"' in installer
    assert a.INSTALLED in (SCRIPT.parent / 'agentporter-dev-autodiscovery.service').read_text()
    # Model the observed private ancestor and the dedicated installation modes.
    def accessible(modes):
        return all(mode & stat.S_IXOTH for mode in modes)
    assert not accessible([0o755, 0o755, 0o700, 0o755])
    assert accessible([0o755, 0o755, 0o755])


def test_unit_retains_setuid_for_child_under_seccomp_and_no_new_privileges():
    unit = (SCRIPT.parent / 'agentporter-dev-autodiscovery.service').read_text()
    # systemd's keep_seccomp_privileges path drops CAP_SETUID unless ambient.
    assert 'AmbientCapabilities=CAP_SETUID' in unit.splitlines()
    assert 'NoNewPrivileges=true' in unit.splitlines()


def test_child_launch_has_exact_dropped_identity_and_clean_environment(monkeypatch):
    class Account:
        pw_uid = 994
        pw_gid = 981
    monkeypatch.setattr(a.pwd, 'getpwnam', lambda name: Account())
    calls = []
    monkeypatch.setattr(a.subprocess, 'Popen', lambda *args, **kwargs: calls.append((args, kwargs)))
    a.launch_barrier_child('a' * 32)
    args, kwargs = calls[0]
    assert args[0] == ['/usr/bin/python3', '-I', a.INSTALLED, '--admission-barrier', '--guard-token', 'a' * 32]
    assert kwargs['user'] == 994 and kwargs['group'] == 981 and kwargs['extra_groups'] == []
    assert kwargs['env'] == {'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8', 'HOME': '/var/lib/agentporter-dev/home'}
    assert kwargs['cwd'] == '/' and kwargs['close_fds'] is True
    assert 'runuser' not in str(args)


def test_child_failure_reports_bounded_sanitized_stderr():
    process = subprocess.Popen(['/usr/bin/python3', '-I', '-c',
        'import sys;sys.stderr.write("Traceback: inaccessible helper\\x1b[31m\\n"+"x"*1000000);sys.exit(7)'],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE, text=True)
    try:
        process.wait(timeout=0.1)
    except subprocess.TimeoutExpired:
        pass  # A full stderr pipe must not make the diagnostic path hang.
    message = a.child_failure(process, 'Admission barrier failed')
    assert 'Traceback: inaccessible helper' in message
    assert '\x1b' not in message and len(message) <= 4500
    assert process.poll() is not None


def test_child_timeout_diagnostics_terminate_without_unbounded_wait():
    process = subprocess.Popen(['/usr/bin/python3', '-I', '-c',
        'import sys,time;sys.stderr.write("child setup failed\\n");sys.stderr.flush();time.sleep(30)'],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE, text=True)
    with pytest.raises(ValueError, match='child setup failed'):
        a.child_line(process, timeout=0.2)
    assert process.poll() is not None


def test_child_mode_pinned_procfd_database_wal_and_protocol(tmp_path, monkeypatch, capsys):
    import io
    database = tmp_path / 'jobs.db'
    os.chmod(tmp_path, 0o700)
    with sqlite3.connect(database) as db:
        db.execute('PRAGMA journal_mode=WAL')
        db.execute('create table jobs(status text)')
        db.execute('create table job_admissions(id text)')
    os.chmod(database, 0o600)
    class Account:
        pw_uid = os.getuid()
    monkeypatch.setattr(a.pwd, 'getpwnam', lambda name: Account())
    monkeypatch.setattr(a, 'JOBS', str(database))
    monkeypatch.setattr(a.sys, 'stdin', io.StringIO('VERIFY\nRELEASE\n'))
    assert a.barrier_child('a' * 32) == 0
    assert capsys.readouterr().out.splitlines() == ['READY', 'VERIFIED', 'RELEASED']
    with sqlite3.connect(database) as db:
        assert db.execute("select count(*) from sqlite_master where type='trigger'").fetchone()[0] == 0
    assert all(file.stat().st_uid == os.getuid() for file in tmp_path.iterdir())


@pytest.mark.parametrize('status', ['completed', 'failed', 'cancelled', 'timed_out', 'output_limit_exceeded', 'interrupted'])
def test_known_terminal_job_history_allows_barrier(tmp_path, status):
    database = tmp_path / 'jobs.db'
    with sqlite3.connect(database) as db:
        db.execute('create table jobs(status text)')
        db.execute('create table job_admissions(id text)')
        db.execute('insert into jobs values (?)', (status,))
    with a.admission_transaction(str(database)):
        pass


@pytest.mark.parametrize('status', ['queued', 'running', 'cancelling', 'cleanup_failed', 'unknown'])
def test_nonterminal_or_unknown_history_blocks_barrier(tmp_path, status):
    database = tmp_path / 'jobs.db'
    with sqlite3.connect(database) as db:
        db.execute('create table jobs(status text)')
        db.execute('create table job_admissions(id text)')
        db.execute('insert into jobs values (?)', (status,))
    with pytest.raises(a.Busy):
        with a.admission_transaction(str(database)):
            pass
