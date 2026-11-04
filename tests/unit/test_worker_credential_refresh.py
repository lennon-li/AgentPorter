"""Exercise the whole refresh orchestration with synthetic credential files.

Only root identity/staging are simulated. Reads, directory pinning, atomic
publishes, permissions and seven separate credential copies are real.
"""
import importlib.util
import os
from pathlib import Path
from types import SimpleNamespace

import pytest


@pytest.fixture(params=['refresh-development-worker-credentials.py'])
def refresh(tmp_path, monkeypatch, request):
    path = Path(__file__).resolve().parents[2] / 'scripts' / request.param
    spec = importlib.util.spec_from_file_location('refresh_orchestration', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    data = tmp_path / 'credentials'
    data.mkdir(mode=0o700)
    stage = tmp_path / 'stage'
    stage.mkdir(mode=0o700)
    uid, gid = os.getuid(), os.getgid()

    class Location:
        parent = SimpleNamespace(stat=lambda: SimpleNamespace(st_uid=0, st_mode=0o40700))

        def is_dir(self):
            return data.is_dir()

        def is_symlink(self):
            return data.is_symlink()

        def stat(self):
            return data.stat()

        def __truediv__(self, other):
            return data / other

    monkeypatch.setattr(module, 'DATA', Location())
    if hasattr(module, 'STAGING'):
        monkeypatch.setattr(module, 'STAGING', stage)
        monkeypatch.setattr(module, '_prepare_staging', lambda: None)
    monkeypatch.setattr(module.os, 'geteuid', lambda: 0)
    monkeypatch.setattr(module.pwd, 'getpwnam', lambda name: SimpleNamespace(pw_uid=uid, pw_gid=gid))
    sources = {}
    for name in ('codex_review', 'codex_impl', 'codex_research', 'claude_agent', 'opencode_free', 'copilot_agent', 'agy_agent'):
        (data / name).mkdir(mode=0o700)
        directory = data / name / 'profile'
        directory.mkdir(mode=0o700)
        source = tmp_path / (name + '-synthetic')
        source.write_text('SYNTHETIC-' + name)
        source.chmod(0o600)
        sources[name] = {'profile/auth.json': str(source)}
    route = tmp_path / 'canonical-route'
    route.write_text('model_provider = "headroom"\n')
    route.chmod(0o600)
    codex = data / 'codex_review/.codex'
    codex.mkdir(mode=0o700)
    (codex / 'config.toml').write_text('model_provider = "existing-route"\n')
    (codex / 'config.toml').chmod(0o600)
    sources['codex_review']['.codex/config.toml'] = str(route)
    monkeypatch.setattr(module, 'SOURCES', sources)
    original_install = module._install_secret

    def install(path, content, owner, group):
        return original_install(path, content, owner, group, staging_dir=stage, staging_uid=uid)

    monkeypatch.setattr(module, '_install_secret', install)
    return module, data, sources


def test_entire_seven_agent_apply_rotation_and_route_preservation(refresh, capsys):
    module, data, sources = refresh
    agents = list(sources)
    module._run(apply=False, agents=agents)
    assert not (data / 'codex_review/profile/auth.json').exists()
    module._run(apply=True, agents=agents)
    for name in agents:
        path = data / name / 'profile/auth.json'
        assert path.read_text() == 'SYNTHETIC-' + name
        assert path.stat().st_mode & 0o777 == 0o600
    assert (data / 'codex_review/.codex/config.toml').read_text() == 'model_provider = "existing-route"\n'
    Path(sources['claude_agent']['profile/auth.json']).write_text('ROTATED-SYNTHETIC-CLAUDE_AGENT')
    module._run(apply=True, agents=['claude_agent'])
    assert (data / 'claude_agent/profile/auth.json').read_text() == 'ROTATED-SYNTHETIC-CLAUDE_AGENT'
    assert (data / 'codex_review/profile/auth.json').read_text() == 'SYNTHETIC-codex_review'
    output = capsys.readouterr().out
    assert 'SYNTHETIC' not in output
    assert 'provider_config_not_auto_refreshed' in output


def test_entire_apply_rejects_nonprivate_destination_before_write(refresh):
    module, data, _ = refresh
    (data / 'codex_review/profile').chmod(0o755)
    with pytest.raises(PermissionError):
        module._run(apply=True, agents=['codex_review'])
    assert not (data / 'codex_review/profile/auth.json').exists()


def test_gateway_explicit_direct_codex_review_route_preserves_owner_config_and_model(refresh,capsys):
    import json,tomllib
    module,data,sources=refresh
    if not hasattr(module,'_codex_review_direct_openai'): pytest.skip('Gateway-specific route repair')
    directory=data/'codex_review/.codex'
    auth=directory/'auth.json'
    auth.write_text(json.dumps({'auth_mode':'chatgpt','tokens':{'access_token':'SYNTHETIC-OAUTH'}}));auth.chmod(0o600)
    config=directory/'config.toml'
    config.write_text('model = "gpt-6.1-sol"\nmodel_provider = "headroom"\n[model_providers.headroom]\nbase_url = "http://127.0.0.1:1234/v1"\n');config.chmod(0o600)
    owner_before=Path(sources['codex_review']['.codex/config.toml']).read_bytes()
    before=config.read_bytes()
    module._codex_review_direct_openai(apply=False)
    assert config.read_bytes()==before
    module._codex_review_direct_openai(apply=True)
    parsed=tomllib.loads(config.read_text())
    assert parsed['model_provider']=='openai'
    assert parsed['model']=='gpt-6.1-sol'
    assert Path(sources['codex_review']['.codex/config.toml']).read_bytes()==owner_before
    assert 'SYNTHETIC-OAUTH' not in capsys.readouterr().out


def test_gateway_direct_codex_review_route_refuses_api_billing_key(refresh):
    import json
    module,data,_=refresh
    if not hasattr(module,'_codex_review_direct_openai'): pytest.skip('Gateway-specific route repair')
    auth=data/'codex_review/.codex/auth.json'
    auth.write_text(json.dumps({'auth_mode':'apikey','OPENAI_API_KEY':'SYNTHETIC-API-KEY'}));auth.chmod(0o600)
    before=(data/'codex_review/.codex/config.toml').read_bytes()
    with pytest.raises(PermissionError,match='ChatGPT OAuth'):
        module._codex_review_direct_openai(apply=True)
    assert (data/'codex_review/.codex/config.toml').read_bytes()==before
