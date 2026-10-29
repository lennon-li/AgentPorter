"""Security contracts and real, synthetic-credential OS worker launches."""
from __future__ import annotations

import json
import errno
import os
from pathlib import Path
import pwd
import shutil
import subprocess

import pytest
import yaml

from agentporter.agents.development import DevelopmentRuntime
from agentporter.agents.roster import PUBLIC_AGENT_IDS
from agentporter.workspaces.registry import WorkspaceRegistry


@pytest.fixture
def runtime_factory(tmp_path):
    """Only synthetic fixture credentials; never load an actual worker profile."""
    counter = 0

    def make(**overrides):
        nonlocal counter
        base = tmp_path / str(counter)
        counter += 1
        base.mkdir()
        config_dir = base / "config"
        config_dir.mkdir()
        workspace = base / "workspace"
        workspace.mkdir()
        other = base / "other-workspace"
        other.mkdir()
        (workspace / "source.txt").write_text("source")
        workers = {}
        helper = base / "codex-code-mode-host"
        shutil.copy2("/usr/bin/true", helper)
        for agent in PUBLIC_AGENT_IDS:
            auth = base / f"{agent}-synthetic-auth.json"
            auth.write_text(json.dumps({"fixture_identity": agent}))
            auth.chmod(0o600)
            workers[agent] = {"executable": "/usr/bin/python3", "credentials": {".codex/auth.json": str(auth)}}
            if agent in {"jax", "liz", "prof"}:
                workers[agent]["code_mode_host"] = str(helper)
        config = {
            "enabled": True, "profile": "development", "production_uid": os.getuid() + 10000,
            "gateway_user": pwd.getpwuid(os.getuid()).pw_name, "network_enabled": False,
            "workers": workers, **overrides,
        }
        config.setdefault("allowed_workspace_roots", [
            {"path": str(workspace), "writable": True},
            {"path": str(other), "writable": True},
        ])
        if 'production_relay_agents' in config:
            config.setdefault('public_client_policy_required', True)
            config.setdefault('job_resources', {'memory_bytes':4*1024**3,'pids':128,
                                               'cpu_quota_us':200000,'cpu_period_us':100000})
        config_path = config_dir / "development-runtime.yaml"
        config_path.write_text(yaml.safe_dump(config))
        registry = WorkspaceRegistry({
            "selected": {"path": str(workspace), "allow_agent_dispatch": True},
            "other": {"path": str(other), "allow_agent_dispatch": True},
        })
        return DevelopmentRuntime(config_dir, base / "state", registry), config, config_path, workspace, other

    return make


def save(config, path):
    path.write_text(yaml.safe_dump(config))


@pytest.mark.parametrize('enabled', [False, True])
def test_only_approved_parallel_mcp_enters_confined_codex(runtime_factory, monkeypatch, enabled):
    import tomllib
    runtime, config, path, workspace, _ = runtime_factory(parallel_search_enabled=enabled)
    profile = path.parent / 'canonical-profile'
    profile.mkdir()
    canonical = profile / 'config.toml'
    canonical.write_text('model = "gpt-6.1-sol"\n[mcp_servers.unapproved]\ncommand = "/host/private/tool"\n')
    canonical.chmod(0o600)
    config['workers']['jax']['credentials']['.codex/config.toml'] = str(canonical)
    save(config, path)
    no_probe(monkeypatch, runtime)
    launch = runtime.prepare('jax', str(workspace), False, ['/usr/bin/python3', '--version'])
    try:
        private = Path(launch.command[launch.command.index('/home/worker') - 1])
        data = tomllib.loads((private / '.codex/config.toml').read_text())
        assert set(data.get('mcp_servers', {})) == ({'parallel-search'} if enabled else set())
        if enabled:
            assert data['mcp_servers']['parallel-search']['url'] == 'https://search.parallel.ai/mcp'
            assert data['mcp_servers']['parallel-search']['enabled_tools'] == ['web_search','web_fetch']
        assert '/host/private/tool' not in repr(launch.command)
    finally:
        launch.cleanup()


def no_probe(monkeypatch, runtime):
    monkeypatch.setattr(runtime, "_probe", lambda *args: None)


@pytest.mark.parametrize('enabled', [False, True])
def test_phil_confined_mcp_uses_cli_file_reference_not_bare_json_argument(runtime_factory, monkeypatch, enabled):
    runtime, _, _, workspace, _ = runtime_factory(parallel_search_enabled=enabled)
    no_probe(monkeypatch, runtime)
    launch = runtime.prepare('phil', str(workspace), False,
        ['/usr/bin/python3', '--version', '--deny-tool=write',
         '--additional-mcp-config', '{"mcpServers":{"unapproved":{}}}'])
    try:
        command = launch.command
        assert '--unshare-all' in command and '--deny-tool=write' in command
        assert 'unapproved' not in repr(command)
        assert ('--additional-mcp-config' in command) is enabled
        if enabled:
            argument = command[command.index('--additional-mcp-config') + 1]
            # Native Copilot --help requires @ for a file; a bare absolute path
            # is parsed as JSON and fails before any provider can run.
            assert argument == '@/home/worker/.config/agentporter/parallel-search-copilot.json'
            home = Path(command[command.index('/home/worker') - 1])
            config = home / '.config/agentporter/parallel-search-copilot.json'
            assert config.stat().st_mode & 0o777 == 0o600
            assert json.loads(config.read_text()) == {'mcpServers': {'parallel-search': {
                'type': 'http', 'url': 'https://search.parallel.ai/mcp',
                'tools': ['web_search', 'web_fetch']}}}
    finally:
        launch.cleanup()


def test_origin_broker_mounts_only_public_ca_and_keeps_namespace(runtime_factory, monkeypatch):
    runtime, config, path, workspace, _ = runtime_factory()
    config.update(network_enabled=True, egress_policy="provider_origin")
    save(config, path)
    no_probe(monkeypatch, runtime)
    launch = runtime.prepare("liz", str(workspace), False, ["/usr/bin/python3", "--version"])
    try:
        args = launch.command
        ca_path = "/run/agentporter-provider-ca.pem"
        index = args.index(ca_path)
        assert args[index - 2] == "--ro-bind"
        bundle = Path(args[index - 1])
        assert bundle.is_file() and b"PRIVATE KEY" not in bundle.read_bytes()
        assert b"BEGIN CERTIFICATE" in bundle.read_bytes()
        assert not any("key.pem" in value for value in args)
        assert "--share-net" not in args and "--unshare-all" in args
        for name in ("SSL_CERT_FILE", "CODEX_CA_CERTIFICATE", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE", "NODE_EXTRA_CA_CERTS"):
            index = args.index(name)
            assert args[index - 1] == "--setenv" and args[index + 1] == ca_path
    finally:
        launch.cleanup()


@pytest.mark.parametrize('policy', ['provider_origin', 'public_https'])
@pytest.mark.parametrize('has_profile', [False, True])
def test_codex_inspectable_body_profile_preserves_provider_route(runtime_factory, monkeypatch, policy, has_profile):
    import tomllib
    runtime, config, path, workspace, _ = runtime_factory(egress_policy=policy)
    profile = path.parent / 'canonical-profile'
    profile.mkdir()
    canonical = profile / 'config.toml'
    original = ('model = "gpt-6.1-sol"\nmodel_provider = "headroom"\n'
                '[model_providers.headroom]\nname = "Headroom"\n'
                'base_url = "http://127.0.0.1:9787/v1"\nwire_api = "responses"\n')
    canonical.write_text(original)
    canonical.chmod(0o600)
    if has_profile:
        config['workers']['jax']['credentials']['.codex/config.toml'] = str(canonical)
    save(config, path)
    no_probe(monkeypatch, runtime)
    launch = runtime.prepare('jax', str(workspace), False, ['/usr/bin/python3', '--version'])
    try:
        private = Path(launch.command[launch.command.index('/home/worker') - 1])
        staged = private / '.codex/config.toml'
        data = tomllib.loads(staged.read_text()) if staged.exists() else {}
        expected = tomllib.loads(original) if has_profile else {}
        assert data.pop('features', {}) == ({'enable_request_compression': False}
                                          if policy == 'provider_origin' else {})
        assert data == expected
        assert canonical.read_text() == original
    finally:
        launch.cleanup()


def test_unknown_network_policy_cannot_fall_back_to_public_egress(runtime_factory, monkeypatch):
    runtime, config, path, workspace, _ = runtime_factory()
    config.update(network_enabled=True, egress_policy="misspelled")
    save(config, path)
    no_probe(monkeypatch, runtime)
    with pytest.raises(PermissionError, match="Unknown development egress policy"):
        runtime.prepare("liz", str(workspace), False, ["/usr/bin/python3", "--version"])


@pytest.mark.parametrize("network,policy,admitted", [
    (True, "provider_origin", True), (True, "public_https", False),
    (True, None, False), (False, "provider_origin", False)])
def test_production_relay_requires_effective_origin_policy(runtime_factory, network, policy, admitted):
    runtime, config, path, _, _ = runtime_factory()
    config.update(network_enabled=network, egress_policy=policy,
                  production_relay_agents=['liz', 'prof', 'ming'], public_client_policy_required=True,
                  job_resources={'memory_bytes':4*1024**3,'pids':128,'cpu_quota_us':200000,'cpu_period_us':100000})
    save(config, path)
    if admitted:
        runtime.require_production_egress()
    else:
        with pytest.raises(PermissionError, match="Production relay requires"):
            runtime.require_production_egress()


@pytest.mark.parametrize('approved', [None, [], {}, 'liz', ['liz', 'liz'], ['unknown'], [True], [['liz']]])
def test_production_relay_requires_explicit_valid_agent_admissions(runtime_factory, approved):
    runtime, config, path, _, _ = runtime_factory(network_enabled=True, egress_policy='provider_origin')
    config['production_relay_agents'] = approved
    save(config, path)
    with pytest.raises(PermissionError, match='explicit admitted agent list'):
        runtime.require_production_egress()


def test_production_relay_denies_unadmitted_workers(runtime_factory):
    runtime, _, _, _, _ = runtime_factory(network_enabled=True, egress_policy='provider_origin',
                                         production_relay_agents=['liz', 'prof', 'ming'])
    assert runtime.require_production_egress() == frozenset({'liz', 'prof', 'ming'})
    for agent in PUBLIC_AGENT_IDS:
        if agent in {'liz', 'prof', 'ming'}:
            runtime.require_production_egress(agent)
        else:
            with pytest.raises(PermissionError, match='not admitted'):
                runtime.require_production_egress(agent)


@pytest.mark.parametrize('missing',['job_resources','public_client_policy_required'])
def test_production_relay_cannot_skip_ingress_or_resource_envelopes(runtime_factory,missing):
    runtime,config,path,_,_=runtime_factory(network_enabled=True,egress_policy='provider_origin',
        production_relay_agents=['liz','prof'])
    config.pop(missing)
    save(config,path)
    with pytest.raises(PermissionError,match='public-client isolation and job resource'):
        runtime.require_production_egress('liz')


def test_assembled_relay_auth_and_admissions_prevent_unverified_dispatch(runtime_factory, temp_config, monkeypatch):
    import asyncio
    from types import SimpleNamespace
    import httpx
    from agentporter import server

    runtime, _, _, workspace, _ = runtime_factory(network_enabled=True, egress_policy='provider_origin',
                                                production_relay_agents=['liz', 'prof', 'ming'])
    registry = WorkspaceRegistry({'selected': {'path': str(workspace), 'allow_agent_dispatch': True}})
    relay_key = 'r' * 43
    key = temp_config.config_dir / 'delegation-relay.key'
    key.write_text(relay_key)
    key.chmod(0o600)
    scope = temp_config.config_dir / 'delegation-relay-scope.yaml'
    scope.write_text(yaml.safe_dump({'version': 1, 'workspaces': {'selected': str(workspace)}}))
    scope.chmod(0o600)
    launches = []
    job_id = 'job_' + 'b' * 24
    def dispatch(**arguments):
        launches.append(arguments)
        return {'job_id': job_id, 'status': 'running'}
    context = {
        'client_policy': SimpleNamespace(scopes=None, internal_key=None),
        'registry': registry, 'agent_broker': SimpleNamespace(development_runtime=runtime),
        'delegation_relay_client': None,
        'job_manager': SimpleNamespace(active_processes={}, get_status=lambda _: {'status': 'completed'}),
        'tools': {'list_agents': lambda: [{'agent': agent, 'available': True, 'delegatable': True}
                                        for agent in PUBLIC_AGENT_IDS],
                  'dispatch_agent': dispatch, 'job_status': lambda **_: {'status': 'completed'}},
    }
    mcp = server.MCPServer('relay-admission-test')
    monkeypatch.setattr(server, 'build_mcp_server', lambda _: (mcp, context))
    app = server.create_asgi_app(temp_config)

    async def exercise():
        transport = httpx.ASGITransport(app=app, client=('127.0.0.1', 12345))
        async with httpx.AsyncClient(transport=transport, base_url='http://127.0.0.1:8876') as client:
            async def call(operation, arguments, token=relay_key):
                return await client.post('/internal/delegation/v1',
                    headers={'Authorization': 'Bearer ' + token},
                    json={'operation': operation, 'args': arguments})
            assert (await call('list_agents', {}, temp_config.api_key)).status_code == 401
            assert (await client.get('/api/v1/workspaces',
                headers={'Authorization': 'Bearer ' + relay_key})).status_code == 401
            inventory = await call('list_agents', {})
            assert inventory.status_code == 200
            assert {row['agent'] for row in inventory.json() if row['delegatable']} == {'liz', 'prof', 'ming'}
            base = {'task': 'Read synthetic file', 'workspace_id': 'selected', 'request_id': 'a' * 32}
            for agent in ('jax', 'wei', 'phil', 'argie'):
                assert (await call('dispatch_agent', {**base, 'agent': agent})).status_code == 403
            assert not launches
            assert (await call('dispatch_agent', {**base, 'agent': 'prof', 'allow_push': True})).status_code == 403
            def capacity_rejected(**arguments):
                raise server.JobCapacityError('Known rejection before any launch')
            context['tools']['dispatch_agent']=capacity_rejected
            for i in range(5):
                assert (await call('dispatch_agent',{**base,'request_id':format(i+1,'032x'),'agent':'prof'})).status_code==429
            context['tools']['dispatch_agent']=dispatch
            accepted = await call('dispatch_agent', {**base, 'agent': 'prof'})
            assert accepted.status_code == 200 and accepted.json()['job_id'] == job_id
            assert len(launches) == 1
            assert (await call('dispatch_agent', {**base, 'agent': 'prof'})).status_code == 200
            assert len(launches) == 1
            context['tools']['job_status']=lambda **_:{'status':'interrupted'}
            recovered=await call('job_status', {'job_id': job_id})
            assert recovered.status_code == 200 and recovered.json()['status']=='interrupted'
            from agentporter.agents.production_relay import RelayLedger
            assert RelayLedger(temp_config.state_dir).active_jobs()==[]
            assert (await call('job_status', {'job_id': 'job_' + 'c' * 24})).status_code == 403
    asyncio.run(exercise())


@pytest.mark.parametrize("rows", [None, [], {}, ["/tmp"], [{"path": "relative", "writable": True}],
                                  [{"path": "/tmp", "writable": "yes"}],
                                  [{"path": "/tmp", "writable": True, "extra": True}]])
def test_workspace_allowlist_missing_or_malformed_fails_closed(runtime_factory, rows):
    runtime, config, path, workspace, _ = runtime_factory(allowed_workspace_roots=rows)
    with pytest.raises(PermissionError, match="allowlist"):
        runtime._workspace(str(workspace), False, config)
    assert runtime.status("jax")["delegatable"] is False


def test_discovered_production_leaf_is_outside_operator_scope(runtime_factory):
    runtime, config, _, workspace, _ = runtime_factory()
    production = workspace.parent / "production-AgentPorter"
    production.mkdir()
    runtime.workspace_registry.register("discovered-production", str(production), allow_agent_dispatch=True)
    with pytest.raises(PermissionError, match="operator development allowlist"):
        runtime._workspace(str(production), False, config)


def test_unapproved_discovered_child_neither_grants_scope_nor_revokes_approved_parent(runtime_factory):
    runtime, config, _, workspace, _ = runtime_factory()
    child = workspace / "discovered-child"
    child.mkdir()
    runtime.workspace_registry.register("discovered-child", str(child), allow_agent_dispatch=True)
    assert runtime._workspace(str(workspace), False, config) == workspace
    with pytest.raises(PermissionError, match="operator development allowlist"):
        runtime._workspace(str(child), False, config)
    config["allowed_workspace_roots"].append({"path": str(child), "writable": False})
    with pytest.raises(PermissionError, match="broad parent of another approved workspace"):
        runtime._workspace(str(workspace), False, config)
    assert runtime._workspace(str(child), False, config) == child


def test_operator_allowlist_and_registry_writability_are_intersected(runtime_factory):
    runtime, config, _, workspace, _ = runtime_factory()
    config["allowed_workspace_roots"][0]["writable"] = False
    assert runtime._workspace(str(workspace), False, config) == workspace
    with pytest.raises(PermissionError, match="read-only delegation"):
        runtime._workspace(str(workspace), True, config)
    config["allowed_workspace_roots"][0]["writable"] = True
    runtime.workspace_registry.get("selected").writable = False
    with pytest.raises(PermissionError, match="read-only delegation"):
        runtime._workspace(str(workspace), True, config)


def test_readonly_approved_parent_and_all_descendants_allow_readonly_launch(runtime_factory, monkeypatch):
    runtime, config, config_path, workspace, _ = runtime_factory()
    child = workspace / "child"
    grandchild = child / "grandchild"
    grandchild.mkdir(parents=True)
    runtime.workspace_registry.register("child", str(child), allow_agent_dispatch=True)
    runtime.workspace_registry.register("grandchild", str(grandchild), allow_agent_dispatch=True)
    config["allowed_workspace_roots"][0]["writable"] = False
    config["allowed_workspace_roots"].extend([
        {"path": str(child), "writable": False},
        {"path": str(grandchild), "writable": False},
    ])
    save(config, config_path)
    for selected in (workspace, child, grandchild):
        assert runtime._workspace(str(selected), False, config) == selected
    no_probe(monkeypatch, runtime)
    launch = runtime.prepare("jax", str(workspace), False, ["/usr/bin/python3", "--version"])
    try:
        mount = launch.command.index("/workspace")
        assert launch.command[mount - 2] == "--ro-bind"
    finally:
        launch.cleanup()
    with pytest.raises(PermissionError, match="read-only delegation"):
        runtime._workspace(str(workspace), True, config)


@pytest.mark.parametrize("writable_node", ["parent", "child", "grandchild"])
def test_nested_approved_parent_rejects_any_writable_descendant_or_parent(runtime_factory, writable_node):
    runtime, config, _, workspace, _ = runtime_factory()
    child = workspace / "child"
    grandchild = child / "grandchild"
    grandchild.mkdir(parents=True)
    nodes = {"parent": workspace, "child": child, "grandchild": grandchild}
    config["allowed_workspace_roots"] = [
        {"path": str(node), "writable": name == writable_node}
        for name, node in nodes.items()
    ]
    with pytest.raises(PermissionError, match="broad parent of another approved workspace"):
        runtime._workspace(str(workspace), False, config)
    # A write request can never take the nested read-only exception either.
    with pytest.raises(PermissionError, match="read-only delegation|broad parent of another approved workspace"):
        runtime._workspace(str(workspace), True, config)


def test_status_reports_only_authoritatively_admitted_workspaces(runtime_factory, monkeypatch):
    runtime, config, config_path, workspace, other = runtime_factory()
    child = workspace / "child"
    child.mkdir()
    runtime.workspace_registry.register("child", str(child), allow_agent_dispatch=True)
    config["allowed_workspace_roots"][0]["writable"] = False
    config["allowed_workspace_roots"].append({"path": str(child), "writable": False})
    for name, options in (
        ("unadmitted", {"allow_agent_dispatch": True}),
        ("no-execute", {"allow_agent_dispatch": True, "allow_execute": False}),
        ("no-dispatch", {"allow_agent_dispatch": False}),
    ):
        root = workspace.parent / name
        root.mkdir()
        runtime.workspace_registry.register(name, str(root), **options)
        if name != "unadmitted":
            config["allowed_workspace_roots"].append({"path": str(root), "writable": False})
    # Even an allowlisted, registry-enabled root is excluded when it contains
    # gateway configuration. Discovery and registry permission alone cannot
    # override the runtime's protected-path check.
    protected = runtime.config_dir
    runtime.workspace_registry.register("protected", str(protected), writable=False, allow_agent_dispatch=True)
    config["allowed_workspace_roots"].append({"path": str(protected), "writable": False})
    save(config, config_path)
    no_probe(monkeypatch, runtime)
    status = runtime.status("jax")
    assert status["delegatable"], status
    assert status["runtime_dispatch_workspaces"] == ["child", "other", "selected"]


def test_real_nested_readonly_workspace_cannot_write_parent_or_descendants(runtime_factory, monkeypatch):
    runtime, config, config_path, workspace, _ = runtime_factory()
    child = workspace / "child"
    grandchild = child / "grandchild"
    grandchild.mkdir(parents=True)
    config["allowed_workspace_roots"][0]["writable"] = False
    for root in (child, grandchild):
        (root / "source.txt").write_text("unchanged")
        config["allowed_workspace_roots"].append({"path": str(root), "writable": False})
    save(config, config_path)
    no_probe(monkeypatch, runtime)
    script = """from pathlib import Path
for relative in ('source.txt', 'child/source.txt', 'child/grandchild/source.txt'):
    path = Path('/workspace') / relative
    assert path.read_text() in ('source', 'unchanged')
    try: path.write_text('forbidden')
    except OSError: pass
    else: raise AssertionError('wrote read-only nested workspace: ' + relative)
print('NESTED_READONLY_OK')
"""
    launch = runtime.prepare("jax", str(workspace), False, ["/usr/bin/python3", "-c", script])
    try:
        result = runtime._run_probe(launch.command, launch.pass_fds)
        assert result.returncode == 0, result.stderr
        assert result.stdout.strip() == "NESTED_READONLY_OK"
        assert (workspace / "source.txt").read_text() == "source"
        assert all((root / "source.txt").read_text() == "unchanged" for root in (child, grandchild))
    finally:
        launch.cleanup()


def test_allowlist_rejects_duplicate_and_symlink_roots(runtime_factory):
    runtime, config, _, workspace, _ = runtime_factory()
    config["allowed_workspace_roots"].append(dict(config["allowed_workspace_roots"][0]))
    with pytest.raises(PermissionError, match="unique canonical directories"):
        runtime._allowed_workspace_roots(config)
    alias = workspace.parent / "alias"
    alias.symlink_to(workspace, target_is_directory=True)
    config["allowed_workspace_roots"] = [{"path": str(alias), "writable": True}]
    with pytest.raises(PermissionError, match="unique canonical directories"):
        runtime._allowed_workspace_roots(config)


@pytest.mark.parametrize("agent", sorted(PUBLIC_AGENT_IDS))
def test_all_seven_require_live_probe(runtime_factory, monkeypatch, agent):
    runtime, *_ = runtime_factory()
    calls = []
    monkeypatch.setattr(runtime, "_probe", lambda *args: calls.append(args[0]))
    assert runtime.status(agent)["delegatable"] is True
    assert calls == [agent]
    assert runtime.status(agent)["delegatable"] is True
    assert calls == [agent]


@pytest.mark.parametrize("overrides,reason", [
    ({"enabled": False}, "not explicitly enabled"),
    ({"profile": "production"}, "not explicitly enabled"),
    ({"production_uid": os.getuid()}, "production UID"),
    ({"production_uid": None}, "production_uid"),
    ({"production_uid": True}, "production_uid"),
    ({"gateway_user": "agentporter-no-such-fixture-account"}, "does not exist"),
    ({"gateway_user": ""}, "separate gateway_user"),
])
def test_identity_and_profile_fail_closed_before_probe(runtime_factory, monkeypatch, overrides, reason):
    runtime, *_ = runtime_factory(**overrides)
    monkeypatch.setattr(runtime, "_probe", lambda *args: pytest.fail("identity failure reached probe"))
    status = runtime.status("jax")
    assert status["delegatable"] is False
    assert reason in status["availability_reason"]


def test_probe_failure_never_enables_or_caches(runtime_factory, monkeypatch):
    runtime, *_ = runtime_factory()
    calls = []

    def failed(*args):
        calls.append(args)
        raise PermissionError("fixture confinement failed")

    monkeypatch.setattr(runtime, "_probe", failed)
    for _ in range(2):
        assert not runtime.status("jax")["delegatable"]
    assert len(calls) == 2
    assert runtime._cache == {}


def test_individual_missing_executable_and_auth_status(runtime_factory, monkeypatch):
    runtime, config, path, *_ = runtime_factory()
    no_probe(monkeypatch, runtime)
    config["workers"]["liz"]["executable"] = "/definitely/missing/fixture/cli"
    Path(config["workers"]["prof"]["credentials"][".codex/auth.json"]).unlink()
    save(config, path)
    assert runtime.status("jax")["delegatable"]
    assert "executable unavailable" in runtime.status("liz")["availability_reason"]
    assert not runtime.status("prof")["delegatable"]
    assert not runtime.status("unknown")["delegatable"]


def test_credential_modes_symlinks_and_hardlink_sharing_rejected(runtime_factory, monkeypatch):
    runtime, config, path, *_ = runtime_factory()
    no_probe(monkeypatch, runtime)
    auth = Path(config["workers"]["jax"]["credentials"][".codex/auth.json"])
    auth.chmod(0o644)
    assert "private ownership/mode" in runtime.status("jax")["availability_reason"]
    auth.chmod(0o600)
    link = auth.with_name("symlink-auth")
    link.symlink_to(auth)
    config["workers"]["jax"]["credentials"][".codex/auth.json"] = str(link)
    save(config, path)
    assert "non-symlink" in runtime.status("jax")["availability_reason"]
    link.unlink()
    os.link(auth, link)
    config["workers"]["jax"]["credentials"][".codex/auth.json"] = str(auth)
    config["workers"]["liz"]["credentials"][".codex/auth.json"] = str(link)
    save(config, path)
    assert "credentials are shared" in runtime.status("jax")["availability_reason"]


def test_workspace_authorization_and_readonly_enforced(runtime_factory, monkeypatch):
    runtime, config, path, workspace, _ = runtime_factory()
    no_probe(monkeypatch, runtime)
    runtime.workspace_registry.get("selected").allow_agent_dispatch = False
    with pytest.raises(PermissionError, match="not authorized"):
        runtime.prepare("jax", str(workspace), False, ["/usr/bin/python3", "--version"])
    runtime.workspace_registry.get("selected").allow_agent_dispatch = True
    runtime.workspace_registry.get("selected").writable = False
    with pytest.raises(PermissionError, match="read-only"):
        runtime.prepare("jax", str(workspace), True, ["/usr/bin/python3", "--version"])
    runtime.workspace_registry.register("broad", str(workspace.parent), allow_agent_dispatch=True)
    with pytest.raises(PermissionError, match="worker-writable workspace|registered development workspaces|broad parent"):
        runtime.prepare("jax", str(workspace.parent), False, ["/usr/bin/python3", "--version"])


def test_mount_topology_private_home_no_host_environment(runtime_factory, monkeypatch):
    runtime, config, _, workspace, other = runtime_factory()
    no_probe(monkeypatch, runtime)
    git = workspace / ".git"
    git.mkdir()
    (git / "config").write_text("safe fixture Git config")
    nested = workspace / "nested"
    nested.mkdir()
    (nested / ".git").mkdir()
    (nested / ".env").write_text("secret")
    (workspace / ".aws").mkdir()
    (workspace / "runtime").mkdir()
    launch = runtime.prepare("jax", str(workspace), True, ["/usr/bin/python3", "--version"],
                             env={"AWS_SECRET_ACCESS_KEY": "never-inherit", "LD_PRELOAD": "evil"})
    try:
        args = launch.command
        assert args[0] == "/usr/bin/bwrap"
        for flag in ("--unshare-all", "--unshare-user", "--disable-userns", "--cap-drop", "--new-session", "--clearenv"):
            assert flag in args
        assert "--share-net" not in args
        assert "never-inherit" not in args
        assert str(other) not in args
        assert str(Path.home()) not in args
        assert "/workspace/.git" in args
        assert "/workspace/nested/.git" in args
        assert "/workspace/nested/.env" in args
        assert "/workspace/runtime" in args
        assert launch.pass_fds
        # Source object is pinned, rather than resolved again by bwrap later.
        git_arg = args.index("/workspace/.git")
        assert args[git_arg - 2] == "--ro-bind"
        fd = int(args[git_arg - 1].rsplit("/", 1)[1])
        assert os.fstat(fd).st_ino == git.stat().st_ino
        home_arg = args.index("/home/worker")
        private_home = Path(args[home_arg - 1])
        assert json.loads((private_home / ".codex/auth.json").read_text()) == {"fixture_identity": "jax"}
        assert sorted(p.name for p in private_home.rglob("auth.json")) == ["auth.json"]
    finally:
        launch.cleanup()
        launch.cleanup()
    for descriptor in launch.pass_fds:
        with pytest.raises(OSError):
            os.fstat(descriptor)


def test_git_source_pinned_against_later_symlink_swap(runtime_factory, monkeypatch):
    runtime, _, _, workspace, other = runtime_factory()
    no_probe(monkeypatch, runtime)
    git = workspace / ".git"
    git.mkdir()
    (git / "marker").write_text("metadata")
    launch = runtime.prepare("jax", str(workspace), True, ["/usr/bin/python3", "--version"])
    try:
        args = launch.command
        source = args[args.index("/workspace/.git") - 1]
        git.rename(workspace / "saved-metadata")
        git.symlink_to(other, target_is_directory=True)
        assert (Path(source) / "marker").read_text() == "metadata"
    finally:
        launch.cleanup()


def test_real_workspace_root_swap_before_mask_scan_keeps_git_readonly(runtime_factory, monkeypatch):
    runtime, _, _, workspace, _ = runtime_factory()
    assert runtime.status("jax")["delegatable"]
    (workspace / ".git").mkdir()
    (workspace / ".git" / "protected").write_text("original metadata")
    original_masks = runtime._masks
    saved = workspace.with_name("saved-original-workspace")

    def swap_then_scan(pinned, writable):
        workspace.rename(saved)
        workspace.mkdir()
        return original_masks(pinned, writable)

    monkeypatch.setattr(runtime, "_masks", swap_then_scan)
    script = """from pathlib import Path
assert Path('/workspace/.git/protected').read_text() == 'original metadata'
try:
    Path('/workspace/.git/protected').write_text('forbidden')
except OSError:
    print('original Git protected')
else:
    raise AssertionError('Git mask missing after root swap')
"""
    launch = runtime.prepare("jax", str(workspace), True, ["/usr/bin/python3", "-c", script])
    try:
        result = subprocess.run(launch.command, env={}, pass_fds=launch.pass_fds, capture_output=True, text=True, timeout=15)
        assert result.returncode == 0, result.stderr
        assert result.stdout.strip() == "original Git protected"
        assert (saved / ".git/protected").read_text() == "original metadata"
    finally:
        launch.cleanup()


def test_deep_metadata_pins_keep_only_final_descriptors(tmp_path):
    from agentporter.agents.development import DevelopmentRuntime
    import resource
    root = tmp_path / 'root'; root.mkdir()
    for index in range(180):
        (root / str(index) / 'nested' / 'deep' / '.git').mkdir(parents=True)
    descriptors = []
    root_fd = os.open(root, os.O_PATH | os.O_DIRECTORY)
    before = resource.getrlimit(resource.RLIMIT_NOFILE)
    try:
        resource.setrlimit(resource.RLIMIT_NOFILE, (256, before[1]))
        for index in range(180):
            fd = DevelopmentRuntime._pin(Path(str(index)) / 'nested/deep/.git', descriptors, root_fd)
            assert os.fstat(fd).st_ino == (root / str(index) / 'nested/deep/.git').stat().st_ino
        assert len(descriptors) == 180
    finally:
        resource.setrlimit(resource.RLIMIT_NOFILE, before)
        for fd in descriptors: os.close(fd)
        os.close(root_fd)


def test_nested_symlink_git_external_worktree_and_hardlinks_fail_closed(runtime_factory, monkeypatch):
    runtime, _, _, workspace, other = runtime_factory()
    no_probe(monkeypatch, runtime)
    nested = workspace / "nested"
    nested.mkdir()
    git = nested / ".git"
    git.symlink_to(other)
    with pytest.raises(PermissionError, match="symlinked Git"):
        runtime.prepare("jax", str(workspace), True, ["/usr/bin/python3", "--version"])
    git.unlink()
    git.write_text(f"gitdir: {other}\n")
    with pytest.raises(PermissionError, match="external Git worktree"):
        runtime.prepare("jax", str(workspace), True, ["/usr/bin/python3", "--version"])
    git.unlink()
    outside = other / "outside"
    outside.write_text("cannot write this through an alias")
    os.link(outside, workspace / "hardlinked")
    with pytest.raises(PermissionError, match="hardlinked"):
        runtime.prepare("jax", str(workspace), True, ["/usr/bin/python3", "--version"])


@pytest.mark.parametrize('filename', ['root', 'outside', 'parent-traversal', 'missing'])
def test_unreadable_masks_never_hide_invalid_or_root_scan_failure(runtime_factory, monkeypatch, filename):
    runtime, _, _, workspace, other = runtime_factory()
    errors = {'root': str(workspace), 'outside': str(other),
              'parent-traversal': str(workspace) + '/child/../private', 'missing': None}

    def failed_walk(path, *, followlinks, onerror):
        onerror(PermissionError(errno.EACCES, 'synthetic scan denial', errors[filename]))
        return iter(())

    monkeypatch.setattr(os, 'walk', failed_walk)
    with pytest.raises(PermissionError, match='cannot inspect'):
        runtime._masks(workspace, False)


def test_unreadable_masks_keep_writable_and_other_io_failures_fatal(runtime_factory, monkeypatch):
    runtime, _, _, workspace, _ = runtime_factory()
    private = workspace / 'private'
    private.mkdir()
    failure = PermissionError(errno.EACCES, 'synthetic denial', str(private))

    def failed_walk(path, *, followlinks, onerror):
        onerror(failure)
        return iter(())

    monkeypatch.setattr(os, 'walk', failed_walk)
    assert runtime._masks(workspace, False) == [(Path('private'), True, False, True)]
    with pytest.raises(PermissionError, match='cannot inspect'):
        runtime._masks(workspace, True)
    for code in (errno.ELOOP, errno.EIO, errno.ENOENT):
        failure = OSError(code, 'synthetic non-permission failure', str(private))
        with pytest.raises(PermissionError, match='cannot inspect'):
            runtime._masks(workspace, False)


def test_unreadable_mask_path_cannot_be_replaced_by_symlink(runtime_factory, monkeypatch):
    runtime, _, _, workspace, other = runtime_factory()
    no_probe(monkeypatch, runtime)
    (workspace / 'private').symlink_to(other, target_is_directory=True)

    def failed_walk(path, *, followlinks, onerror):
        onerror(PermissionError(errno.EACCES, 'synthetic scan denial', str(Path(path) / 'private')))
        return iter(())

    monkeypatch.setattr(os, 'walk', failed_walk)
    with pytest.raises(PermissionError, match='changed to a symlink'):
        runtime.prepare('jax', str(workspace), False, ['/usr/bin/python3', '--version'])


def test_real_readonly_unreadable_subtree_is_opaque_without_host_permission_changes(runtime_factory, monkeypatch):
    runtime, _, _, workspace, _ = runtime_factory()
    no_probe(monkeypatch, runtime)
    private = workspace / 'private'
    private.mkdir()
    (private / 'hidden.txt').write_text('PRIVATE_NEVER_EXPOSE')
    private.chmod(0o000)
    launch = None
    try:
        with pytest.raises(PermissionError):
            list(private.iterdir())
        script = """from pathlib import Path
assert Path('/workspace/source.txt').read_text() == 'source'
assert Path('/workspace/private').stat().st_mode & 0o777 == 0
for action in (lambda: list(Path('/workspace/private').iterdir()),
               lambda: Path('/workspace/private/hidden.txt').read_text(),
               lambda: Path('/workspace/private/new').write_text('forbidden')):
    try: action()
    except OSError: pass
    else: raise AssertionError('opaque subtree access granted')
print('OPAQUE_SUBTREE_OK')
"""
        launch = runtime.prepare('jax', str(workspace), False, ['/usr/bin/python3', '-c', script])
        result = runtime._run_probe(launch.command, launch.pass_fds)
        assert result.returncode == 0, result.stderr
        assert result.stdout.strip() == 'OPAQUE_SUBTREE_OK'
        assert private.stat().st_mode & 0o777 == 0
        with pytest.raises(PermissionError, match='cannot inspect'):
            runtime.prepare('jax', str(workspace), True, ['/usr/bin/python3', '--version'])
    finally:
        if launch is not None:
            launch.cleanup()
        private.chmod(0o700)
    assert (private / 'hidden.txt').read_text() == 'PRIVATE_NEVER_EXPOSE'
    assert not (private / 'new').exists()
    assert not list(runtime.state_dir.glob('development-*'))


def test_real_readonly_external_worktree_hides_control_file_and_external_configuration(runtime_factory, monkeypatch):
    runtime, _, _, workspace, other = runtime_factory()
    no_probe(monkeypatch, runtime)
    config = other / 'config'
    config.write_text('[include]\npath = /host/private/never-load\n')
    (workspace / '.git').write_text(f'gitdir: {other}\n')
    script = f"""from pathlib import Path
assert Path('/workspace/source.txt').read_text() == 'source'
assert Path('/workspace/.git').read_bytes() == b''
assert not Path({str(other)!r}).exists()
try: Path('/workspace/.git').write_text('forbidden')
except OSError: pass
else: raise AssertionError('Git metadata writable')
print('EXTERNAL_GIT_HIDDEN')
"""
    launch = runtime.prepare('jax', str(workspace), False, ['/usr/bin/python3', '-c', script])
    try:
        result = runtime._run_probe(launch.command, launch.pass_fds)
        assert result.returncode == 0, result.stderr
        assert result.stdout.strip() == 'EXTERNAL_GIT_HIDDEN'
        assert str(other) not in launch.command
        assert config.read_text() == '[include]\npath = /host/private/never-load\n'
        assert (workspace / '.git').read_text() == f'gitdir: {other}\n'
    finally:
        launch.cleanup()
    with pytest.raises(PermissionError, match='external Git worktree'):
        runtime.prepare('jax', str(workspace), True, ['/usr/bin/python3', '--version'])


def test_codex_wrapper_normalized_and_configuration_screened(runtime_factory, monkeypatch):
    runtime, config, path, workspace, _ = runtime_factory()
    no_probe(monkeypatch, runtime)
    source = path.parent / "codex-config.toml"
    # Existing cleaner reads config.toml beneath this explicit source parent.
    source = source.with_name("config.toml")
    source.write_text('model = "fixture-model"\n[mcp_servers.forbidden]\ncommand = "host-tool"\n')
    source.chmod(0o600)
    config["workers"]["jax"]["codex_config"] = str(source)
    save(config, path)
    launch = runtime.prepare("jax", str(workspace), True, [
        "/usr/bin/python3", "-I", "-m", "agentporter.agents.isolated_codex",
        "--source-home", "/never/expose/production", "--workspace", str(workspace), "--",
        "/usr/bin/python3", "exec", "-C", str(workspace), "--sandbox", "workspace-write", "fixture-prompt",
    ])
    try:
        args = launch.command
        assert "/never/expose/production" not in args
        assert args[-6:] == ["exec", "-C", "/workspace", "--sandbox", "danger-full-access", "fixture-prompt"]
        home = Path(args[args.index("/home/worker") - 1])
        text = (home / ".codex/config.toml").read_text()
        assert 'model = "fixture-model"' in text
        assert "mcp_servers" not in text
    finally:
        launch.cleanup()


@pytest.mark.parametrize("source,target", [
    ("/opt", "/opt/agentporter/runtime/tools"),
    ("/usr", "/opt/agentporter/runtime/tools"),
    ("/home", "/opt/agentporter/runtime/tools"),
    ("/usr/bin/python3", "/home/worker/override"),
])
def test_broad_or_privileged_tool_mounts_rejected(runtime_factory, monkeypatch, source, target):
    runtime, config, path, workspace, _ = runtime_factory()
    no_probe(monkeypatch, runtime)
    config["workers"]["jax"]["runtime_mounts"] = [{"source": source, "target": target}]
    save(config, path)
    with pytest.raises(PermissionError, match="runtime mount"):
        runtime.prepare("jax", str(workspace), True, ["/usr/bin/python3", "--version"])


def test_real_synthetic_worker_boundaries(runtime_factory):
    """Run on the host when tool-level sandbox blocks namespace/netlink setup."""
    runtime, _, _, workspace, other = runtime_factory()
    (workspace / ".git").mkdir()
    (workspace / ".git/config").write_text("metadata")
    (workspace / ".env").write_text("production-like fixture secret")
    (other / "private").write_text("other workspace secret")
    status = runtime.status("jax")
    assert status["delegatable"], status["availability_reason"]
    assert status["verified_modes"] == ["read-only", "writable"]
    script = f"""import pathlib, os, socket
assert not pathlib.Path({str(other)!r}).exists()
assert pathlib.Path('/workspace/.env').read_text() == ''
assert pathlib.Path('/workspace/.git/config').read_text() == 'metadata'
assert 'never-inherit' not in str(dict(os.environ))
# No pinned source handles may survive into the worker. Such a directory
# descriptor could bypass the read-only Git overlay through /proc/self/fd.
for name in os.listdir('/proc/self/fd'):
    try: target = os.readlink('/proc/self/fd/' + name)
    except FileNotFoundError: continue
    assert {str(workspace)!r} not in target, ('workspace source fd leaked', target)
    assert {str(runtime.state_dir)!r} not in target, ('runtime source fd leaked', target)
for target in ['/workspace/.git/config', '/usr/forbidden']:
    try: pathlib.Path(target).write_text('bad')
    except OSError: pass
    else: raise AssertionError(target)
pathlib.Path('/workspace/source.txt').write_text('changed')
try: socket.create_connection(('127.0.0.1', 22), timeout=0.3)
except OSError: pass
else: raise AssertionError('host loopback exposed')
print('fixture worker completed')
"""
    launch = runtime.prepare("jax", str(workspace), True, ["/usr/bin/python3", "-c", script],
                             env={"AWS_SECRET_ACCESS_KEY": "never-inherit"})
    try:
        result = subprocess.run(launch.command, env={}, pass_fds=launch.pass_fds, capture_output=True, text=True, timeout=15)
        assert result.returncode == 0, result.stderr
        assert "fixture worker completed" in result.stdout
        assert (workspace / "source.txt").read_text() == "changed"
        assert (workspace / ".git/config").read_text() == "metadata"
    finally:
        launch.cleanup()
    script = "from pathlib import Path\ntry: Path('/workspace/source.txt').write_text('forbidden')\nexcept OSError: print('readonly enforced')\nelse: raise AssertionError('wrote read-only workspace')"
    launch = runtime.prepare("jax", str(workspace), False, ["/usr/bin/python3", "-c", script])
    try:
        result = subprocess.run(launch.command, env={}, pass_fds=launch.pass_fds, capture_output=True, text=True, timeout=15)
        assert result.returncode == 0, result.stderr
        assert result.stdout.strip() == "readonly enforced"
    finally:
        launch.cleanup()


@pytest.mark.parametrize("agent", sorted(PUBLIC_AGENT_IDS))
def test_real_all_seven_confined_executable_probes(runtime_factory, agent):
    runtime, *_ = runtime_factory()
    status = runtime.status(agent)
    assert status["delegatable"], status["availability_reason"]
    assert status["cli_version"].startswith("Python ")


def test_launcher_and_configuration_must_be_outside_writable_workspaces(runtime_factory):
    runtime, *_ = runtime_factory()
    from agentporter.agents import development

    runtime.workspace_registry.register("launcher", str(Path(development.__file__).resolve().parents[1]), allow_agent_dispatch=True)
    assert "launcher source overlaps" in runtime.status("jax")["availability_reason"]
    runtime.workspace_registry.get("launcher").allow_agent_dispatch = False
    runtime.workspace_registry.register("config", str(runtime.config_dir), allow_agent_dispatch=True)
    assert "runtime configuration overlaps" in runtime.status("jax")["availability_reason"]


@pytest.mark.parametrize("shared_snapshot", [False, True])
@pytest.mark.parametrize("writable", [False, True])
def test_argie_stages_only_explicit_antigravity_token(runtime_factory, monkeypatch, tmp_path, shared_snapshot, writable):
    runtime, config, path, workspace, _ = runtime_factory()
    no_probe(monkeypatch, runtime)
    profile = path.parent.parent / "fake-gemini-profile"
    (profile / "antigravity-cli").mkdir(parents=True)
    token = profile / "antigravity-cli" / "antigravity-oauth-token"
    token.write_text("synthetic-antigravity-oauth-token")
    token.chmod(0o600)
    (profile / "settings.json").write_text('{"mcpServers":{"forbidden":{}},"hooks":{"forbidden":[]}}')
    (profile / "oauth_creds.json").write_text("unrelated-synthetic-gemini-credential")
    config["workers"]["argie"]["credentials"] = {
        ".gemini/antigravity-cli/antigravity-oauth-token": str(token),
    }
    config["workers"]["argie"]["model"] = "Gemini 3.8 Flash (Medium)"
    if shared_snapshot:
        snapshot = tmp_path / "shared-obsidian"
        for relative in (
            "Toolbox/claude-skills/synthetic-skill/SKILL.md",
            "AgentSystem/agent-memory/skills/INDEX.md",
            "AgentSystem/agent-memory/boot/AGENT_STARTUP_PROTOCOL.md",
            "tools/agent-tool-policy.json",
            "tools/AGENT_TOOL_HANDOFF.md",
        ):
            target = snapshot / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text("synthetic admitted shared content")
        monkeypatch.setattr(runtime, "_shared_obsidian_source", lambda _: snapshot)
        config["shared_obsidian"] = str(snapshot)
    save(config, path)
    (workspace / ".gemini").mkdir()
    (workspace / ".gemini" / "settings.json").write_text("workspace secrets must be masked")
    launch = runtime.prepare("argie", str(workspace), writable, ["/usr/bin/python3", "--version"])
    try:
        args = launch.command
        private_home = Path(args[args.index("/home/worker") - 1])
        staged = private_home / ".gemini" / "antigravity-cli" / "antigravity-oauth-token"
        assert staged.read_text() == "synthetic-antigravity-oauth-token"
        assert staged.stat().st_mode & 0o777 == 0o600
        settings = private_home / ".gemini/antigravity-cli/settings.json"
        assert json.loads(settings.read_text())["model"] == "Gemini 3.8 Flash (Medium)"
        assert settings.stat().st_mode & 0o777 == 0o600
        policy = json.loads(settings.read_text())
        shared_reads = (
            ["read_file(/opt/agentporter/shared/obsidian)"] if shared_snapshot else []
        )
        assert policy["permissions"]["allow"] == ["read_file(/workspace)", *shared_reads,
                                                   *(["write_file(/workspace)"] if writable else [])]
        assert set(policy["permissions"]["deny"]) == {
            "command(*)", *([] if writable else ["write_file(*)"]), "read_url(*)", "execute_url(*)", "mcp(*)",
            "read_file(/home/worker/.gemini/antigravity-cli)",
            "read_file(/home/worker/.config)", "read_file(/home/worker/.local/share)",
        }
        assert "--dangerously-skip-permissions" not in args
        assert {"hooks", "mcpServers"}.isdisjoint(policy)
        assert {item.relative_to(private_home).as_posix() for item in private_home.rglob("*") if item.is_file()} == {
            ".gemini/antigravity-cli/antigravity-oauth-token",
            ".gemini/antigravity-cli/settings.json",
        }
        target_index = args.index("/workspace/.gemini")
        assert args[target_index - 2] == "--ro-bind"
        masked_source = Path(args[target_index - 1])
        assert masked_source.is_dir()
        assert list(masked_source.iterdir()) == []
        assert str(profile) not in args
    finally:
        launch.cleanup()


@pytest.mark.parametrize("version,provider,model", [
    ("1.9.0", "opencode-go", "opencode-go/glm-5.3-flash"),
    ("2.1.1", "opencode-go", "opencode-go/glm-5.3-flash"),
    ("1.9.0", "opencode", "opencode/glm-5.3-flash-free"),
])
def test_wei_explicit_route_private_key_reference_no_environment_or_argv_secret(
    runtime_factory, monkeypatch, version, provider, model,
):
    runtime, config, path, workspace, _ = runtime_factory()
    no_probe(monkeypatch, runtime)
    key = path.parent.parent / "synthetic-wei-key"
    secret = "synthetic-wei-api-key-never-in-arguments"
    key.write_text(secret)
    key.chmod(0o600)
    config["workers"]["wei"].update(provider=provider, model=model,
        credentials={".config/opencode/wei-key": str(key)})
    save(config, path)
    runtime._evidence["wei"] = {"cli_version": version}
    launch = runtime.prepare("wei", str(workspace), False,
        ["/usr/bin/python3", "run", "--agent", "dispatch", "fixture-prompt"],
        env={"OPENCODE_CONFIG_CONTENT": '{"provider":{"vertex":{"options":{"apiKey":"unrelated-key"}}}}'})
    try:
        args = launch.command
        assert secret not in repr(args)
        assert "unrelated-key" not in repr(args)
        assert "OPENCODE_CONFIG_CONTENT" not in args
        assert "OPENCODE_CONFIG" in args
        private_home = Path(args[args.index("/home/worker") - 1])
        private_config = private_home / ".config/opencode/agentporter-development.json"
        profile = json.loads(private_config.read_text())
        assert private_config.stat().st_mode & 0o777 == 0o600
        assert profile["model"] == model
        assert set(profile["provider"]) == {provider}
        options = profile["provider"][provider]["options"]
        assert options["apiKey"] == "{file:/home/worker/.config/opencode/wei-key}"
        assert secret not in private_config.read_text()
        assert (private_home / ".config/opencode/wei-key").read_text() == secret
        assert args[-5:] == ["--model", model, "--agent", "dispatch", "fixture-prompt"]
        assert ("--standalone" in args) == version.startswith("2.")
        if provider == "opencode-go":
            assert options["baseURL"] == "https://opencode.ai/inference/go/openai/v1"
            assert profile["provider"][provider]["npm"] == "@ai-sdk/openai-compatible"
    finally:
        launch.cleanup()


@pytest.mark.parametrize("override", [["-m", "vertex/forbidden"], ["--model=opencode/forbidden-free"], ["-mopencode/forbidden-free"]])
def test_wei_go_key_cannot_change_provider_route(runtime_factory, monkeypatch, override):
    runtime, config, path, workspace, _ = runtime_factory()
    no_probe(monkeypatch, runtime)
    key = path.parent.parent / "synthetic-go-key"
    key.write_text("synthetic-go-key")
    key.chmod(0o600)
    config["workers"]["wei"].update(provider="opencode-go", model="opencode-go/glm-5.3-flash",
        credentials={".config/opencode/wei-key": str(key)})
    save(config, path)
    runtime._evidence["wei"] = {"cli_version": "2.1.1"}
    with pytest.raises(PermissionError, match="differs from the provisioned"):
        runtime.prepare("wei", str(workspace), False, ["/usr/bin/python3", "run", *override, "fixture-prompt"])
    assert not list(runtime.state_dir.glob("development-wei-*"))
    config["workers"]["wei"]["model"] = "vertex/forbidden"
    save(config, path)
    status = runtime.status("wei")
    assert not status["delegatable"]
    assert "no fallback" in status["availability_reason"]


def test_codex_helper_required_trusted_outside_workspace_and_signature(runtime_factory, monkeypatch):
    runtime, config, path, workspace, _ = runtime_factory()
    probes = []
    monkeypatch.setattr(runtime, '_probe', lambda *args: probes.append(args[0]))
    assert runtime.status('jax')['delegatable']
    helper = Path(config['workers']['jax']['code_mode_host'])
    helper.write_bytes(helper.read_bytes() + b'cache-change')
    assert runtime.status('jax')['delegatable']
    assert len(probes) == 2
    helper.chmod(0o777)
    assert 'trusted executable ownership/mode' in runtime.status('jax')['availability_reason']
    helper.chmod(0o755)
    copied = workspace / 'codex-code-mode-host'
    shutil.copy2(helper, copied)
    config['workers']['jax']['code_mode_host'] = str(copied)
    save(config, path)
    assert 'outside registered development workspaces' in runtime.status('jax')['availability_reason']
    del config['workers']['jax']['code_mode_host']
    save(config, path)
    assert 'helper is not configured' in runtime.status('jax')['availability_reason']


def test_codex_helper_readonly_mount_uses_pinned_fd(runtime_factory, monkeypatch):
    runtime, config, _, workspace, _ = runtime_factory()
    no_probe(monkeypatch, runtime)
    launch = runtime.prepare('prof', str(workspace), False, ['/usr/bin/python3', '--version'])
    try:
        index = launch.command.index('/opt/agentporter/codex-code-mode-host')
        assert launch.command[index - 2] == '--ro-bind'
        source = launch.command[index - 1]
        assert source.startswith('/proc/self/fd/')
        fd = int(source.rsplit('/', 1)[1])
        assert fd in launch.pass_fds
        assert os.fstat(fd).st_ino == Path(config['workers']['prof']['code_mode_host']).stat().st_ino
    finally:
        launch.cleanup()
    with pytest.raises(OSError):
        os.fstat(fd)


def test_real_bundled_codex_helper_admin_launch_inside_boundary(runtime_factory, monkeypatch):
    helper = Path('/home/operator/.codex/packages/standalone/releases/0.163.0-x86_64-unknown-linux-musl/bin/codex-code-mode-host')
    if not helper.is_file():
        pytest.skip('optional installed upstream bundled Codex helper unavailable on this host')
    runtime, config, path, workspace, _ = runtime_factory()
    config['workers']['jax']['code_mode_host'] = str(helper)
    save(config, path)
    no_probe(monkeypatch, runtime)
    script = """import subprocess
result = subprocess.run(['/opt/agentporter/codex-code-mode-host', '--help'],
    stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=5)
assert result.returncode == 0, result.stderr
assert 'Usage:' in result.stdout
print('CODE_MODE_HELPER_ADMIN_OK')
"""
    launch = runtime.prepare('jax', str(workspace), False, ['/usr/bin/python3', '-c', script])
    try:
        outcome = runtime._run_probe(launch.command, launch.pass_fds)
        assert outcome.returncode == 0, outcome.stderr
        assert 'CODE_MODE_HELPER_ADMIN_OK' in outcome.stdout
    finally:
        launch.cleanup()


@pytest.mark.parametrize('model', ['', '\nGemini Flash', 'x' * 161, {'mcpServers': {}}])
def test_argie_model_settings_reject_unsafe_values(runtime_factory, monkeypatch, model):
    runtime, config, path, *_ = runtime_factory()
    no_probe(monkeypatch, runtime)
    token = Path(config['workers']['argie']['credentials']['.codex/auth.json'])
    config['workers']['argie'].update(
        credentials={'.gemini/antigravity-cli/antigravity-oauth-token': str(token)}, model=model)
    save(config, path)
    status = runtime.status('argie')
    assert not status['delegatable']
    assert 'bounded printable model name' in status['availability_reason']


def test_writable_inventory_uses_exact_runtime_workspace_gate(runtime_factory, monkeypatch):
    runtime, config, _, workspace, other = runtime_factory()
    monkeypatch.setattr(runtime, '_verified', lambda _: (config, runtime._spec('jax', config)))
    config['allowed_workspace_roots'][1]['writable'] = False
    status = runtime.status('jax')
    assert status['runtime_dispatch_workspaces'] == ['other', 'selected']
    assert status['runtime_writable_dispatch_workspaces'] == ['selected']
    runtime.workspace_registry.get('selected').writable = False
    assert runtime.status('jax')['runtime_writable_dispatch_workspaces'] == []
