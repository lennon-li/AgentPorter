"""Exercise the whole refresh orchestration with synthetic credential files.

Only root identity/staging are simulated. Reads, directory pinning, atomic
publishes, permissions and seven separate credential copies are real.
"""
import importlib.util
import os
from pathlib import Path
from types import SimpleNamespace

import pytest


@pytest.fixture
def refresh(tmp_path, monkeypatch):
    path = Path(__file__).resolve().parents[1] / 'scripts/refresh-development-worker-credentials.py'
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
    monkeypatch.setattr(module.os, 'geteuid', lambda: 0)
    monkeypatch.setattr(module.pwd, 'getpwnam', lambda name: SimpleNamespace(pw_uid=uid, pw_gid=gid))
    sources = {}
    for name in ('jax', 'liz', 'prof', 'ming', 'wei', 'phil', 'argie'):
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
    codex = data / 'jax/.codex'
    codex.mkdir(mode=0o700)
    (codex / 'config.toml').write_text('model_provider = "existing-route"\n')
    (codex / 'config.toml').chmod(0o600)
    sources['jax']['.codex/config.toml'] = str(route)
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
    assert not (data / 'jax/profile/auth.json').exists()
    module._run(apply=True, agents=agents)
    for name in agents:
        path = data / name / 'profile/auth.json'
        assert path.read_text() == 'SYNTHETIC-' + name
        assert path.stat().st_mode & 0o777 == 0o600
    assert (data / 'jax/.codex/config.toml').read_text() == 'model_provider = "existing-route"\n'
    Path(sources['ming']['profile/auth.json']).write_text('ROTATED-SYNTHETIC-MING')
    module._run(apply=True, agents=['ming'])
    assert (data / 'ming/profile/auth.json').read_text() == 'ROTATED-SYNTHETIC-MING'
    assert (data / 'jax/profile/auth.json').read_text() == 'SYNTHETIC-jax'
    output = capsys.readouterr().out
    assert 'SYNTHETIC' not in output
    assert 'provider_config_not_auto_refreshed' in output


def test_entire_apply_rejects_nonprivate_destination_before_write(refresh):
    module, data, _ = refresh
    (data / 'jax/profile').chmod(0o755)
    with pytest.raises(PermissionError):
        module._run(apply=True, agents=['jax'])
    assert not (data / 'jax/profile/auth.json').exists()


def test_apply_skips_unpublished_route_before_source_validation(refresh, monkeypatch, capsys):
    module, data, sources = refresh
    route = Path(sources['jax']['.codex/config.toml'])
    route.chmod(0o664)
    original = module._validated_secret
    reads = []
    def validated(path, *args, **kwargs):
        reads.append(path)
        return original(path, *args, **kwargs)
    monkeypatch.setattr(module, '_validated_secret', validated)
    module._run(apply=True, agents=list(sources))
    assert route not in reads
    assert (data / 'ming/profile/auth.json').read_text() == 'SYNTHETIC-ming'
    assert (data / 'phil/profile/auth.json').read_text() == 'SYNTHETIC-phil'
    assert (data / 'argie/profile/auth.json').read_text() == 'SYNTHETIC-argie'
    assert (data / 'jax/.codex/config.toml').read_text() == 'model_provider = "existing-route"\n'
    assert route.stat().st_mode & 0o777 == 0o664
    assert 'provider_config_not_auto_refreshed' in capsys.readouterr().out


def test_check_still_rejects_writable_route_metadata(refresh):
    module, _, sources = refresh
    Path(sources['jax']['.codex/config.toml']).chmod(0o664)
    with pytest.raises(PermissionError):
        module._run(apply=False, agents=list(sources))


def test_original_source_reproduces_unrelated_route_blocks_ming(refresh):
    module, data, sources = refresh
    # Execute the frozen baseline source only against synthetic fixture files.
    import json
    baseline = json.loads((Path(__file__).resolve().parents[1] / 'manifest.json').read_text())
    original = Path(baseline['baseline_source']).read_text()
    namespace = {}
    exec(original, namespace)
    namespace.update(DATA=module.DATA, SOURCES=module.SOURCES, pwd=module.pwd, os=module.os,
                     _install_secret=module._install_secret)
    Path(sources['jax']['.codex/config.toml']).chmod(0o664)
    with pytest.raises(PermissionError):
        namespace['_run'](apply=True, agents=list(sources))
    assert not (data / 'ming/profile/auth.json').exists()


def test_invalid_earlier_profile_does_not_starve_ming_or_phil(refresh, capsys):
    module, data, sources = refresh
    Path(sources['jax']['profile/auth.json']).chmod(0o644)
    with pytest.raises(PermissionError, match='jax'):
        module._run(apply=True, agents=list(sources))
    assert not (data / 'jax/profile/auth.json').exists()
    assert (data / 'ming/profile/auth.json').read_text() == 'SYNTHETIC-ming'
    assert (data / 'phil/profile/auth.json').read_text() == 'SYNTHETIC-phil'
    output = capsys.readouterr().out
    assert 'jax: credential_failed stage=source reason=metadata_rejected' in output
    assert 'SYNTHETIC' not in output


def test_check_failure_continues_profiles_but_remains_nonzero(refresh, capsys):
    module, data, sources = refresh
    Path(sources['jax']['.codex/config.toml']).chmod(0o664)
    with pytest.raises(PermissionError, match='jax'):
        module._run(apply=False, agents=list(sources))
    output = capsys.readouterr().out
    assert 'jax: credential_failed stage=source reason=metadata_rejected' in output
    assert 'ming profile/auth.json: stale_or_absent' in output
    assert not (data / 'ming/profile/auth.json').exists()


def test_publish_error_has_bounded_profile_stage_not_sensitive_message(refresh, monkeypatch, capsys):
    module, data, _ = refresh
    original = module._install_secret
    def install(path, *args):
        if 'jax' in path.parts:
            raise OSError('PRIVATE-CREDENTIAL-EXCEPTION-DETAIL')
        return original(path, *args)
    monkeypatch.setattr(module, '_install_secret', install)
    with pytest.raises(PermissionError, match='jax') as info:
        module._run(apply=True, agents=['jax','ming'])
    output = capsys.readouterr().out
    assert 'jax: credential_failed stage=publish reason=io_failure' in output
    assert 'PRIVATE-CREDENTIAL' not in output + str(info.value)
    assert (data / 'ming/profile/auth.json').read_text() == 'SYNTHETIC-ming'


def test_missing_source_fails_profile_and_does_not_prevent_later_profile(refresh, capsys):
    module, data, sources = refresh
    Path(sources['ming']['profile/auth.json']).unlink()
    with pytest.raises(PermissionError, match='ming'):
        module._run(apply=True, agents=['ming','phil'])
    assert 'ming: credential_failed stage=source reason=missing' in capsys.readouterr().out
    assert not (data / 'ming/profile/auth.json').exists()
    assert (data / 'phil/profile/auth.json').read_text() == 'SYNTHETIC-phil'


def test_explicit_routes_still_validate_route_metadata(refresh):
    module, _, sources = refresh
    Path(sources['jax']['.codex/config.toml']).chmod(0o664)
    with pytest.raises(PermissionError):
        module._describe_codex_route('jax')
