"""Operator helper validates dry runs and relocatable offline installation."""
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import shutil
from types import SimpleNamespace

import pytest


@pytest.fixture
def provision():
    path = Path(__file__).parents[2] / 'scripts/provision-development-runtime.py'
    spec = importlib.util.spec_from_file_location('development_provision', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_copy_rejects_external_links_without_following(provision, tmp_path):
    source = tmp_path / 'source'
    source.mkdir()
    (source / 'escape').symlink_to('/etc')
    destination = tmp_path / 'copy'
    with pytest.raises(ValueError, match='external symlink'):
        provision.copy_tree(source, destination)
    assert (destination / 'escape').is_symlink()
    assert list(destination.iterdir()) == [destination / 'escape']


@pytest.mark.parametrize('mutation', ['missing', 'extra', 'redirected', 'disabled', 'writable_type'])
def test_workspace_admission_cannot_inherit_discovered_scope(provision, tmp_path, monkeypatch, mutation):
    approved, production = tmp_path / 'approved', tmp_path / 'production'
    approved.mkdir()
    production.mkdir()
    monkeypatch.setattr(provision, 'WORKSPACES', {'approved': str(approved)})
    plan = {'workspaces': {'approved': {'path': str(approved), 'allow_agent_dispatch': True}}}
    if mutation == 'missing':
        plan = None
    elif mutation == 'extra':
        plan['workspaces']['discovered-production'] = {'path': str(production), 'allow_agent_dispatch': True}
    elif mutation == 'redirected':
        plan['workspaces']['approved']['path'] = str(production)
    elif mutation == 'disabled':
        plan['workspaces']['approved']['allow_agent_dispatch'] = False
    else:
        plan['workspaces']['approved']['writable'] = 'yes'
    with pytest.raises(ValueError, match='Workspace admission'):
        provision.workspace_admissions(plan)


def test_atomic_destination_cannot_escape_by_symlink(provision, tmp_path):
    real = tmp_path / 'real'
    real.mkdir()
    alias = tmp_path / 'alias'
    alias.symlink_to(real, target_is_directory=True)
    with pytest.raises(ValueError, match='symlinked'):
        provision.atomic_text(alias / 'key', 'never written', uid=os.getuid(), gid=os.getgid())
    assert not (real / 'key').exists()


def test_system_unit_only_development_identity_paths_port(provision):
    unit = provision.unit_text()
    assert 'User=agentporter-dev\n' in unit
    assert '127.0.0.1 --port 8876' in unit
    assert '/opt/agentporter-development/current/venv/bin/python -I' in unit
    assert 'HOME=/var/lib/agentporter-dev/home' in unit
    assert 'AGENTPORTER_CONFIG_DIR=/var/lib/agentporter-dev/config' in unit
    assert '/home/yeli' not in unit
    assert 'sudo' not in unit
    assert 'NoNewPrivileges=true\n' in unit
    assert 'RestrictSUIDSGID=true\n' in unit
    for directive in ('ProtectKernelTunables', 'ProtectKernelModules', 'ProtectControlGroups',
                      'MountAPIVFS', 'PrivateMounts', 'ProtectProc', 'ProcSubset'):
        assert directive + '=' not in unit


def test_workspace_acl_excludes_secrets_and_readonly_git(provision, tmp_path, monkeypatch):
    workspace = tmp_path / 'workspace'
    workspace.mkdir()
    (workspace / '.git').mkdir()
    (workspace / '.ssh').mkdir()
    (workspace / '.gemini').mkdir()
    (workspace / '.env').write_text('private fixture')
    (workspace / 'source.py').write_text('pass')
    (workspace / 'external').symlink_to('/etc', target_is_directory=True)
    backup = tmp_path / 'backup'
    backup.mkdir()
    calls = []
    monkeypatch.setattr(provision, 'run', lambda argv, **kw: calls.append([str(x) for x in argv]) or SimpleNamespace(stdout=''))
    monkeypatch.setattr(provision, 'atomic_text', lambda path, text, **kw: path.write_text(text))
    provision.grant_workspaces({'workspaces': {'fixture': {'path': str(workspace), 'writable': True}}},
                               SimpleNamespace(pw_uid=12345), backup)
    assert any('u:12345:r-X' in call and '-P' in call and str(workspace / '.git') in call for call in calls)
    assert any('u:12345:---' in call and str(workspace / '.env') in call for call in calls)
    assert any('u:12345:---' in call and str(workspace / '.ssh') in call for call in calls)
    assert any('u:12345:---' in call and str(workspace / '.gemini') in call for call in calls)
    assert not any(str(workspace / 'external') in call for call in calls)
    assert not any('u:12345:rwx' in item and str(Path.home()) in call for call in calls for item in call)


def synthetic_obsidian(tmp_path):
    root = tmp_path / "obsidian-fixture"
    for name in (
        "AgentSystem/agent-memory/skills/INDEX.md",
        "AgentSystem/agent-memory/skills/first-principles-thinking.md",
        "AgentSystem/agent-memory/boot/AGENT_STARTUP_PROTOCOL.md",
        "tools/agent-tool-policy.json",
        "tools/AGENT_TOOL_HANDOFF.md",
    ):
        file = root / name
        file.parent.mkdir(parents=True, exist_ok=True)
        file.write_text("Fixture documentation, no secrets")
    for scope in ("AgentSystem/agent-memory/policies",
                  "AgentSystem/agent-memory/loaders",
                  "Toolbox/claude-skills"):
        (root / scope).mkdir(parents=True)
    (root / 'tools/agent-tool-policy.json').write_text(json.dumps({
        'tools': {'required': [f'fixture-tool-{i}' for i in range(38)]}}))
    # This fixture explicitly represents public shareable documentation,
    # regardless of the operator/test runner's private umask.
    for location, directories, files in os.walk(root):
        Path(location).chmod(0o755)
        for name in files:
            (Path(location) / name).chmod(0o644)
    return root


def test_shared_obsidian_snapshot_is_scoped_readonly_and_deterministic(provision, tmp_path):
    source = synthetic_obsidian(tmp_path)
    destination = tmp_path / "out"
    receipt = provision.stage_shared_obsidian(source, destination)
    assert receipt["files"] == 5
    assert receipt["bytes"] > 0
    assert (destination / "AgentSystem/agent-memory/skills/INDEX.md").is_file()
    assert not ((destination / "AgentSystem/agent-memory/skills/INDEX.md").stat().st_mode & 0o222)
    assert not (destination / "tools/install-agent-tools.sh").exists()
    assert receipt["hashes"]["tools/agent-tool-policy.json"]
    assert provision.stage_shared_obsidian(source, tmp_path / "other")["hashes"] == receipt["hashes"]


def test_shared_obsidian_snapshot_rejects_symlink_escape_and_secret_payload(provision, tmp_path):
    source = synthetic_obsidian(tmp_path)
    target = source / "AgentSystem/agent-memory/skills" / "danger.md"
    target.symlink_to("/etc/passwd")
    with pytest.raises(ValueError, match="bounded regular file"):
        provision.stage_shared_obsidian(source, tmp_path / "bad")
    target.unlink()
    (source / "AgentSystem/agent-memory/skills" / "ignored.pyc").write_bytes(b"host code")
    receipt = provision.stage_shared_obsidian(source, tmp_path / "good")
    assert receipt["files"] == 5
    assert not (tmp_path / "good/AgentSystem/agent-memory/skills/ignored.pyc").exists()


def test_offline_snapshot_interpreter_and_dependencies_relocate(provision, tmp_path, monkeypatch):
    # Exercise the actual installed interpreter and dependencies as this test's
    # unprivileged UID, without system account/service/filesystem mutations.
    monkeypatch.setattr(provision, 'INSTALL', tmp_path / 'install')
    monkeypatch.setattr(provision, 'OBSIDIAN', synthetic_obsidian(tmp_path))
    monkeypatch.setattr(provision, 'immutable_tree', lambda root: None)
    monkeypatch.setattr(provision, 'atomic_text', lambda path, text, **kw: path.write_text(text))
    interpreter = (provision.REPO / '.venv/bin/python').resolve()
    vendor = tmp_path / 'vendor'
    vendor.mkdir()
    shutil.copy2('/usr/bin/true', vendor / 'codex')
    shutil.copy2('/usr/bin/true', vendor / 'codex-code-mode-host')
    monkeypatch.setattr(provision, 'WORKSPACES', {'fixture': str(tmp_path)})
    workspaces = {'workspaces': {'fixture': {'path': str(tmp_path), 'allow_agent_dispatch': True, 'writable': False}}}
    destination, runtime = provision.snapshot({'workers': {'jax': {
        'executable': str(vendor / 'codex'), 'credentials': {}}}}, interpreter.parent.parent, 'fixture', approvals={}, workspaces=workspaces)
    assert runtime['allowed_workspace_roots'] == [{'path': str(tmp_path), 'writable': False}]
    installed_cli = Path(runtime['workers']['jax']['executable'])
    installed_helper = Path(runtime['workers']['jax']['code_mode_host'])
    assert installed_cli.parent == installed_helper.parent
    assert installed_helper.name == 'codex-code-mode-host'
    assert installed_helper.read_bytes() == (vendor / 'codex-code-mode-host').read_bytes()
    assert not list((destination / 'venv/lib/python3.13/site-packages').glob('*editable*agentporter*.pth'))
    result = subprocess.run([str(destination / 'venv/bin/python'), '-I', '-c',
                             'import agentporter, yaml, sys; print(agentporter.__file__); print(sys.prefix)'],
                            capture_output=True, text=True, timeout=30,
                            env={'PATH': '/usr/bin:/bin', 'PYTHONDONTWRITEBYTECODE': '1'})
    assert result.returncode == 0, result.stderr
    assert str(destination / 'src/agentporter') in result.stdout
    assert str(destination / 'venv') in result.stdout
    assert str(provision.REPO / 'src') not in result.stdout


def test_snapshot_missing_matching_codex_helper_fails_closed(provision, tmp_path, monkeypatch):
    monkeypatch.setattr(provision, 'INSTALL', tmp_path / 'install')
    monkeypatch.setattr(provision, 'OBSIDIAN', synthetic_obsidian(tmp_path))
    monkeypatch.setattr(provision, 'atomic_text', lambda path, text, **kw: path.write_text(text))

    def skeleton(source, target, **kwargs):
        target.mkdir()
        if target.name == 'lib':
            (target / 'python3.13/site-packages').mkdir(parents=True)

    monkeypatch.setattr(provision, 'copy_tree', skeleton)
    cli = tmp_path / 'codex'
    shutil.copy2('/usr/bin/true', cli)
    monkeypatch.setattr(provision, 'WORKSPACES', {'fixture': str(tmp_path)})
    workspaces = {'workspaces': {'fixture': {'path': str(tmp_path), 'allow_agent_dispatch': True}}}
    with pytest.raises(ValueError, match='matching bundled Codex code-mode helper is missing'):
        provision.snapshot({'workers': {'prof': {'executable': str(cli), 'credentials': {}}}},
                           tmp_path, 'missing-helper', approvals={}, workspaces=workspaces)


def test_argie_copies_only_verified_oauth_file_not_hooks_or_mcp(provision, tmp_path, monkeypatch):
    target = '.gemini/antigravity-cli/antigravity-oauth-token'
    assert provision.CREDENTIALS['argie'] == {
        target: '/home/yeli/.gemini/antigravity-cli/antigravity-oauth-token'}
    source = tmp_path / 'source' / target
    source.parent.mkdir(parents=True)
    source.write_text('offline-fixture-token')
    (source.parent / 'hooks').mkdir()
    (source.parent / 'hooks/evil.sh').write_text('must never be copied')
    (source.parent / 'mcp.json').write_text('must never be copied')
    destination = tmp_path / 'dev-vault' / target
    monkeypatch.setattr(provision, 'private_dir', lambda path, *args: path.mkdir(parents=True, exist_ok=True))
    monkeypatch.setattr(provision, 'atomic_text', lambda path, text, **kw: path.write_text(text))
    missing = provision.copy_worker_credentials(
        {'workers': {'argie': {'credentials': {target: str(source)}}}},
        {'workers': {'argie': {'credentials': {target: str(destination)}}}},
        SimpleNamespace(pw_uid=os.getuid(), pw_gid=os.getgid()))
    assert not missing
    assert destination.read_text() == 'offline-fixture-token'
    assert list(destination.parent.iterdir()) == [destination]


def test_wei_uses_canonical_go_key_with_private_dev_copy(provision, tmp_path, monkeypatch):
    target = '.config/opencode/wei-key'
    assert provision.CREDENTIALS['wei'] == {target: '/home/yeli/.config/opencode/go-key'}
    source = tmp_path / 'source/go-key'
    source.parent.mkdir()
    source.write_text('offline-go-fixture')
    source.chmod(0o644)
    destination = tmp_path / 'dev-credentials' / target
    account = SimpleNamespace(pw_uid=os.getuid(), pw_gid=os.getgid())
    monkeypatch.setattr(provision, 'private_dir', lambda path, *args: path.mkdir(parents=True, exist_ok=True))
    missing = provision.copy_worker_credentials(
        {'workers': {'wei': {'credentials': {target: str(source)}}}},
        {'workers': {'wei': {'credentials': {target: str(destination)}}}}, account)
    assert not missing
    assert destination.read_text() == 'offline-go-fixture'
    assert destination.stat().st_mode & 0o777 == 0o600
    assert destination.stat().st_uid == account.pw_uid
    assert source.stat().st_mode & 0o777 == 0o644


def test_inventory_runs_live_confined_checks_and_reports_all_blocked(provision, tmp_path, monkeypatch, capsys):
    data = tmp_path / 'dev'
    (data / 'config').mkdir(parents=True)
    (data / 'config/secrets.env').write_text('AGENTPORTER_API_KEY=private-test-key-not-for-output\n')
    rows = [{'agent': agent, 'available': False, 'delegatable': False,
             'confinement_status': 'blocked_development_runtime',
             'availability_reason': 'missing dedicated credential' if agent == 'wei' else 'proc mount EPERM'}
            for agent in provision.AGENTS]
    calls = []

    def urlopen(request, **kwargs):
        calls.append(request)
        return io.BytesIO(json.dumps(rows).encode())

    monkeypatch.setattr(provision, 'DATA', data)
    monkeypatch.setattr(provision.urllib.request, 'urlopen', urlopen)
    assert provision.report_inventory() == rows
    output = capsys.readouterr().out
    assert '0/7' in output and 'proc mount EPERM' in output and 'missing dedicated credential' in output
    assert 'private-test-key-not-for-output' not in output
    assert calls[0].full_url.endswith('/api/v1/workspaces/m3-poc/agents/list')
    assert calls[0].get_header('X-agentporter-key') == 'private-test-key-not-for-output'
