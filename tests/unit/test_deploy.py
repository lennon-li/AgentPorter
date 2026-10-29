"""Deployment fingerprint, deploy-info endpoint, deploy-check CLI, and the human-run deploy script."""

import os
import shutil
import stat
import subprocess
from pathlib import Path

import pytest
from click.testing import CliRunner
from starlette.testclient import TestClient

from agentporter import deployinfo
from agentporter.config import Config
from agentporter.server import create_asgi_app

REPO = Path(__file__).resolve().parents[2]
SCRIPT = REPO / "scripts" / "agentporter-deploy"
KEY = "fixture-only-not-a-real-key"


def test_fingerprint_is_stable_and_tracks_source_edits(tmp_path):
    pkg = tmp_path / "pkg"
    (pkg / "sub" / "__pycache__").mkdir(parents=True)
    (pkg / "a.py").write_text("A = 1\n")
    (pkg / "sub" / "b.py").write_text("B = 2\n")
    first = deployinfo.source_fingerprint(pkg)
    assert first == deployinfo.source_fingerprint(pkg)
    (pkg / "sub" / "__pycache__" / "b.cpython-313.py").write_text("ignored")
    (pkg / "sub" / "b.cpython-313.pyc").write_bytes(b"ignored")
    assert deployinfo.source_fingerprint(pkg) == first
    (pkg / "sub" / "b.py").write_text("B = 3\n")
    second = deployinfo.source_fingerprint(pkg)
    assert second != first
    (pkg / "template.yaml").write_text("walltime: 1h\n")  # data files change behaviour too
    third = deployinfo.source_fingerprint(pkg)
    assert third != second
    (pkg / "evil").symlink_to("/etc")  # links are recorded, never followed
    assert deployinfo.source_fingerprint(pkg) != third


def test_deploy_info_reports_stale_when_disk_differs(monkeypatch):
    info = deployinfo.deploy_info()
    assert info["loaded_fingerprint"] == info["disk_fingerprint"]
    assert info["stale"] is False
    assert Path(info["package_path"]) == deployinfo.PACKAGE_ROOT
    assert info["modules"]["agentporter.server"].startswith(str(deployinfo.PACKAGE_ROOT))
    monkeypatch.setattr(deployinfo, "source_fingerprint", lambda root=None: "0" * 64)
    assert deployinfo.deploy_info()["stale"] is True


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("AGENTPORTER_API_KEY", KEY)
    config = Config(config_dir=tmp_path / "config", state_dir=tmp_path / "state")
    config.workspaces = {}
    return config, TestClient(create_asgi_app(config), base_url="http://127.0.0.1:8765")


def test_deploy_info_endpoint_requires_api_key_and_is_not_an_action(client):
    config, http = client
    assert http.get("/api/v1/server/deploy-info").status_code == 401
    resp = http.get("/api/v1/server/deploy-info", headers={config.security.header_name: KEY})
    assert resp.status_code == 200
    assert resp.json()["loaded_fingerprint"] == deployinfo.loaded_fingerprint()
    assert http.get("/health").json() == {"status": "healthy"}
    ops = {op.get("operationId") for item in http.get("/openapi.json").json()["paths"].values()
           for op in item.values() if isinstance(op, dict)}
    assert "server_deploy_info" not in ops


class _Resp:
    def __init__(self, status, payload):
        self.status_code, self._payload = status, payload

    def json(self):
        return self._payload


@pytest.mark.parametrize("live_fp,stale,path,code,verdict", [
    (None, False, None, 0, "ACTIVE"),
    ("f" * 64, False, None, 1, "STALE"),
    (None, True, None, 1, "STALE"),
    (None, False, "/elsewhere/agentporter", 1, "MISMATCH"),
])
def test_deploy_check_verdicts(monkeypatch, tmp_path, live_fp, stale, path, code, verdict):
    import httpx
    from agentporter.cli import main

    monkeypatch.setenv("AGENTPORTER_API_KEY", KEY)
    payload = {
        "pid": 1, "started_at": "now", "modules": {},
        "package_path": path or str(deployinfo.PACKAGE_ROOT),
        "loaded_fingerprint": live_fp or deployinfo.source_fingerprint(),
        "stale": stale,
    }
    seen = {}

    def fake_get(url, headers, timeout, **kwargs):
        seen.update(url=url, headers=headers)
        return _Resp(200, payload)

    monkeypatch.setattr(httpx, "get", fake_get)
    result = CliRunner().invoke(main, ["deploy-check", "--config-dir", str(tmp_path)])
    assert result.exit_code == code, result.output
    assert f"RESULT: {verdict}" in result.output
    assert seen["url"].endswith("/api/v1/server/deploy-info")
    assert KEY in seen["headers"].values()


def test_deploy_check_unreachable_is_unverified(monkeypatch, tmp_path):
    import httpx
    from agentporter.cli import main

    def boom(*a, **k):
        raise httpx.ConnectError("refused")

    monkeypatch.setattr(httpx, "get", boom)
    result = CliRunner().invoke(main, ["deploy-check", "--config-dir", str(tmp_path)])
    assert result.exit_code == 1
    assert "UNVERIFIED" in result.output


def test_deploy_check_detects_duplicate_port_owner(monkeypatch, tmp_path):
    import httpx
    from agentporter.cli import main

    payload = {"pid": 999, "started_at": "now", "modules": {}, "stale": False,
               "package_path": str(deployinfo.PACKAGE_ROOT),
               "loaded_fingerprint": deployinfo.source_fingerprint()}
    monkeypatch.setattr(httpx, "get", lambda url, headers, timeout, **kwargs: _Resp(200, payload))
    bad = CliRunner().invoke(main, ["deploy-check", "--config-dir", str(tmp_path), "--expect-pid", "4242"])
    assert bad.exit_code == 1 and "MISMATCH" in bad.output and "4242" in bad.output
    ok = CliRunner().invoke(main, ["deploy-check", "--config-dir", str(tmp_path), "--expect-pid", "999",
                                   "--expect-fingerprint", payload["loaded_fingerprint"]])
    assert ok.exit_code == 0 and "ACTIVE" in ok.output


# Repository guard rails: no agent-triggerable activation may ship.

def test_no_agent_triggerable_activation_units_or_scripts():
    examples = REPO / "examples"
    for pattern in ("*.path", "*.timer", "*.socket"):
        assert not list(examples.glob(pattern))
    assert not (REPO / "scripts" / "agentporter-activate").exists()
    assert "enable --now agentporter-activate" not in (REPO / "docs" / "deployment.md").read_text()
    unit = (examples / "agentporter.service").read_text()
    assert [ln for ln in unit.splitlines() if ln.startswith("ExecStart=")] == [
        "ExecStart=%h/.local/share/agentporter/current/venv/bin/python -I -m agentporter.cli "
        "serve --host 127.0.0.1 --port 8765"]
    assert "UnsetEnvironment=PYTHONPATH" in unit


def test_deploy_script_syntax_and_no_tmp_lock_fallback():
    subprocess.run(["bash", "-n", str(SCRIPT)], check=True)
    text = SCRIPT.read_text()
    assert "/tmp" not in text.replace("no /tmp fallback", "")
    assert "scinet-broker" not in text  # deploys never restart the broker
    assert 'UNIT="agentporter.service"' in text


# End-to-end deploy script tests with fake uv/systemctl and a real git repo.

FAKE_PY = r"""#!/bin/bash
if [ "$FAKE_REQUIRE_CLEAN_GATEWAY_ENV" = 1 ]; then
  [ -z "${AGENTPORTER_API_KEY+x}${AGENTPORTER_PROFILE+x}${AGENTPORTER_CONFIG_DIR+x}" ] || exit 83
fi
echo "$*" >> "$FAKE_LOG.python"
pkg="$(dirname "$0")/../lib/python3.13/site-packages/agentporter"
case "$*" in
  *"-m pytest "*) [ -n "$FAKE_TAMPER" ] && echo "TAMPERED = 1" >> "$pkg/__init__.py"; exit "${FAKE_PYTEST_RC:-0}" ;;
  *deploy-check*)
    fp=""; prev=""
    for a in "$@"; do [ "$prev" = "--expect-fingerprint" ] && fp="$a"; prev="$a"; done
    grep -qx "$fp" "$FAKE_GOOD_FPS" ;;
  *) exit 99 ;;
esac
"""

FAKE_UV = r"""#!/bin/bash
if [ "$FAKE_REQUIRE_CLEAN_GATEWAY_ENV" = 1 ]; then
  [ -z "${AGENTPORTER_API_KEY+x}${AGENTPORTER_PROFILE+x}${AGENTPORTER_CONFIG_DIR+x}${AGENTPORTER_STATE_DIR+x}${AGENTPORTER_CACHE_DIR+x}" ] || exit 83
fi
echo "uv $* cwd=$PWD" >> "$FAKE_LOG.uv"
v="$UV_PROJECT_ENVIRONMENT"
mkdir -p "$v/bin" "$v/lib/python3.13/site-packages"
cp -r src/agentporter "$v/lib/python3.13/site-packages/agentporter"
echo "import _virtualenv" > "$v/lib/python3.13/site-packages/_virtualenv.pth"
[ -n "$FAKE_EDITABLE_PTH" ] && echo "$FAKE_EDITABLE_PTH" > "$v/lib/python3.13/site-packages/_editable.pth"
cp "$FAKE_PY_TEMPLATE" "$v/bin/python"; chmod 755 "$v/bin/python"
"""

FAKE_SYSTEMCTL = r"""#!/bin/bash
echo "$*" >> "$FAKE_LOG"
case "$*" in
  *list-unit-files*) [ -f "$FAKE_TRIGGERS" ] && cat "$FAKE_TRIGGERS"; exit 0 ;;
  *ExecStart*) echo "$FAKE_EXEC" ;;
  *MainPID*) echo 4242 ;;
  *stop*) exit "${FAKE_STOP_RC:-0}" ;;
esac
exit 0
"""


def _git(repo, *args):
    return subprocess.run(["git", "-C", str(repo), "-c", "user.name=t", "-c", "user.email=t@t", *args],
                          check=True, capture_output=True, text=True).stdout.strip()


def _commit(repo, body):
    (repo / "src" / "agentporter" / "__init__.py").write_text(body)
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "snapshot")
    return _git(repo, "rev-parse", "HEAD")


def _fp(tmp_path, body):
    pkg = tmp_path / f"fp-{abs(hash(body))}"
    pkg.mkdir(exist_ok=True)
    (pkg / "__init__.py").write_text(body)
    return deployinfo.source_fingerprint(pkg)


class DeployEnv:
    def __init__(self, tmp_path):
        self.tmp = tmp_path
        self.repo = tmp_path / "source"
        (self.repo / "src" / "agentporter").mkdir(parents=True)
        (self.repo / "tests").mkdir()
        (self.repo / "tests" / "conftest.py").write_text("raise SystemExit('workspace conftest must never run')\n")
        subprocess.run(["git", "init", "-q", str(self.repo)], check=True)
        self.sha = _commit(self.repo, "VERSION = 'a'\n")
        tools = tmp_path / "tools"
        tools.mkdir()
        for name, body in (("python-template", FAKE_PY), ("uv", FAKE_UV), ("systemctl", FAKE_SYSTEMCTL)):
            (tools / name).write_text(body)
            (tools / name).chmod(0o755)
        self.libexec = tmp_path / "libexec"
        self.libexec.mkdir()
        self.script = self.libexec / "agentporter-deploy"
        shutil.copy(SCRIPT, self.script)
        self.script.chmod(0o555)
        self.libexec.chmod(0o555)
        run = tmp_path / "run"
        run.mkdir()
        run.chmod(0o700)
        (tmp_path / "cfg" / "systemd" / "user").mkdir(parents=True)
        self.root = tmp_path / "deploy"
        self.good = tmp_path / "good-fps"
        self.good.write_text("")
        self.log = tmp_path / "systemctl.log"
        current_py = f"{self.root}/current/venv/bin/python"
        self.env = {k: v for k, v in os.environ.items() if not k.startswith("FAKE_")}
        self.env.update(
            AGENTPORTER_DEPLOY_ROOT=str(self.root), AGENTPORTER_SOURCE=str(self.repo),
            AGENTPORTER_UV=str(tools / "uv"), AGENTPORTER_SYSTEMCTL=str(tools / "systemctl"),
            XDG_RUNTIME_DIR=str(run), XDG_CONFIG_HOME=str(tmp_path / "cfg"),
            FAKE_LOG=str(self.log), FAKE_PY_TEMPLATE=str(tools / "python-template"),
            FAKE_GOOD_FPS=str(self.good), FAKE_TRIGGERS=str(tmp_path / "triggers"),
            FAKE_EXEC=f"{{ path={current_py} ; argv[]={current_py} -I -m agentporter.cli serve }}",
        )

    def run(self, *args, script=None, **extra):
        proc = subprocess.run([str(script or self.script), *args], env={**self.env, **extra},
                              capture_output=True, text=True)
        return proc.returncode, proc.stdout + proc.stderr

    def calls(self):
        return self.log.read_text().splitlines() if self.log.exists() else []

    def restarts(self):
        return [c for c in self.calls() if "restart" in c]

    def trust(self, body):
        self.good.write_text(self.good.read_text() + _fp(self.tmp, body) + "\n")

    def cleanup(self):
        self.libexec.chmod(0o755)
        for path in self.tmp.rglob("*"):
            if not path.is_symlink():
                path.chmod(path.stat().st_mode | stat.S_IWUSR)


@pytest.fixture
def deploy_env(tmp_path):
    env = DeployEnv(tmp_path)
    yield env
    env.cleanup()


def test_trusted_fingerprint_matches_runtime_algorithm(tmp_path):
    pkg = tmp_path / "pkg"
    (pkg / "sub" / "__pycache__").mkdir(parents=True)
    (pkg / "a.py").write_text("A = 1\n")
    (pkg / "sub" / "data.json").write_text("{}")
    (pkg / "sub" / "__pycache__" / "x.pyc").write_bytes(b"x")
    (pkg / "link").symlink_to("/etc")
    for root in (pkg, deployinfo.PACKAGE_ROOT):
        out = subprocess.run([str(SCRIPT), "fingerprint", str(root)], capture_output=True, text=True, check=True)
        assert out.stdout.strip() == deployinfo.source_fingerprint(root)


def test_happy_deploy_restarts_only_gateway_and_seals_release(deploy_env, tmp_path):
    e = deploy_env
    e.trust("VERSION = 'a'\n")
    marker = tmp_path / "sitecustomize-ran"
    evil = tmp_path / "evil"
    evil.mkdir()
    (evil / "sitecustomize.py").write_text(f"open({str(marker)!r}, 'w')\n")
    code, out = e.run("deploy", e.sha, PYTHONPATH=str(evil))
    assert code == 0, out
    assert "ACTIVE and verified" in out
    assert e.restarts() == ["--user restart agentporter.service"]
    assert not any("broker" in c for c in e.calls())
    assert not marker.exists()
    rel = e.root / "releases" / e.sha
    assert os.readlink(e.root / "current") == f"releases/{e.sha}"
    assert not os.access(rel / "src", os.W_OK)
    assert f'"commit": "{e.sha}"' in (rel / "RELEASE.json").read_text()
    pycalls = Path(f"{e.log}.python").read_text()
    assert "-I -m pytest" in pycalls and "--expect-pid 4242" in pycalls
    assert f"cwd={rel}/src" in Path(f"{e.log}.uv").read_text()  # built from the archived snapshot
    code, out = e.run("status")
    assert code == 0, out


@pytest.mark.parametrize("bad", ["main", "HEAD", "abc123", "../../etc", "--force"])
def test_deploy_requires_pinned_full_sha(deploy_env, bad):
    code, out = deploy_env.run("deploy", bad)
    assert code == 2 and "40-hex" in out
    assert deploy_env.calls() == []


def test_unknown_commit_is_refused(deploy_env):
    code, out = deploy_env.run("deploy", "0" * 40)
    assert code == 2 and "not found" in out
    assert deploy_env.restarts() == []


def test_refuses_to_run_from_writable_workspace_copy(deploy_env):
    code, out = deploy_env.run("deploy", deploy_env.sha, script=SCRIPT)
    assert code == 2 and "REFUSED" in out
    assert deploy_env.calls() == []


@pytest.mark.parametrize("mode", [None, 0o755])
def test_lock_requires_private_runtime_dir(deploy_env, tmp_path, mode):
    runtime = ""
    if mode is not None:
        loose = tmp_path / "loose"
        loose.mkdir()
        loose.chmod(mode)
        runtime = str(loose)
    code, out = deploy_env.run("deploy", deploy_env.sha, XDG_RUNTIME_DIR=runtime)
    assert code == 2 and ("no /tmp fallback" in out or "0700" in out)
    if runtime:
        assert not (Path(runtime) / "agentporter-deploy.lock").exists()
    assert deploy_env.restarts() == []


@pytest.mark.parametrize("where", ["file", "systemd"])
def test_path_trigger_unit_blocks_deploy(deploy_env, tmp_path, where):
    if where == "file":
        (tmp_path / "cfg" / "systemd" / "user" / "agentporter-activate.path").write_text("[Path]\n")
    else:
        (tmp_path / "triggers").write_text("agentporter-activate.path enabled enabled\n")
    code, out = deploy_env.run("deploy", deploy_env.sha)
    assert code == 2 and "path-triggered" in out
    assert deploy_env.restarts() == []


def test_unit_config_drift_to_workspace_venv_is_refused(deploy_env):
    drift = "{ argv[]=/home/u/repos/AgentPorter/.venv/bin/agentporter serve }"
    code, out = deploy_env.run("deploy", deploy_env.sha, FAKE_EXEC=drift)
    assert code == 2 and "config drift" in out
    assert deploy_env.restarts() == []


def test_failing_tests_do_not_activate(deploy_env):
    code, out = deploy_env.run("deploy", deploy_env.sha, FAKE_PYTEST_RC="1")
    assert code == 2 and "tests failed" in out
    assert not (deploy_env.root / "current").exists()
    assert deploy_env.restarts() == []


def test_tampering_during_test_gate_is_detected(deploy_env):
    code, out = deploy_env.run("deploy", deploy_env.sha, FAKE_TAMPER="1")
    assert code == 2 and "fingerprint drift" in out
    assert not (deploy_env.root / "current").exists()
    assert deploy_env.restarts() == []


def test_editable_pth_redirect_is_refused(deploy_env):
    code, out = deploy_env.run("deploy", deploy_env.sha, FAKE_EDITABLE_PTH=str(deploy_env.repo / "src"))
    assert code == 2 and "outside the release" in out
    assert deploy_env.restarts() == []


def test_stale_live_fingerprint_rolls_back_to_previous_release(deploy_env):
    e = deploy_env
    e.trust("VERSION = 'a'\n")
    assert e.run("deploy", e.sha)[0] == 0
    sha_b = _commit(e.repo, "VERSION = 'b'\n")  # the live server never reports b's fingerprint
    code, out = e.run("deploy", sha_b, "--wait", "0")
    assert code == 1, out
    assert "ROLLED BACK" in out
    assert os.readlink(e.root / "current") == f"releases/{e.sha}"
    assert e.restarts() == ["--user restart agentporter.service"] * 3


def test_modified_existing_release_is_refused(deploy_env):
    e = deploy_env
    e.trust("VERSION = 'a'\n")
    assert e.run("deploy", e.sha)[0] == 0
    pkg = next((e.root / "releases" / e.sha / "venv").glob("lib/python3*/site-packages/agentporter"))
    pkg.chmod(0o755)
    (pkg / "__init__.py").chmod(0o644)
    (pkg / "__init__.py").write_text("VERSION = 'evil'\n")
    code, out = e.run("deploy", e.sha)
    assert code == 2 and "was modified" in out
    assert e.restarts() == ["--user restart agentporter.service"]


def test_rollback_without_previous_is_refused(deploy_env):
    code, out = deploy_env.run("rollback")
    assert code == 2 and "no previous release" in out
    assert deploy_env.restarts() == []


def test_prepare_is_inactive_even_with_legacy_unit_and_clears_gateway_environment(deploy_env):
    e = deploy_env
    code, out = e.run('prepare', e.sha, FAKE_EXEC='/mutable/repo/.venv/bin/agentporter',
                      AGENTPORTER_PROFILE='production', AGENTPORTER_API_KEY='wrong-inherited-fixture',
                      AGENTPORTER_CONFIG_DIR='/wrong-gateway-config', FAKE_REQUIRE_CLEAN_GATEWAY_ENV='1')
    assert code == 0 and 'PREPARED and inactive' in out
    assert e.restarts() == []
    assert not (e.root / 'current').exists() and not (e.root / 'previous').exists()
    assert (e.root / 'releases' / e.sha / 'RELEASE.json').is_file()
    assert not any('ExecStart' in call for call in e.calls())


def test_activate_requires_existing_prepared_candidate_and_exact_manifest(deploy_env):
    e = deploy_env
    code, out = e.run('activate', e.sha)
    assert code == 2 and 'not prepared' in out and e.restarts() == []
    assert e.run('prepare', e.sha)[0] == 0
    manifest = e.root / 'releases' / e.sha / 'RELEASE.json'
    manifest.chmod(0o644)
    record = __import__('json').loads(manifest.read_text())
    record['commit'] = '0' * 40
    manifest.write_text(__import__('json').dumps(record))
    manifest.chmod(0o444)
    code, out = e.run('activate', e.sha)
    assert code == 2 and 'manifest' in out and e.restarts() == []
    assert not (e.root / 'current').exists()


def test_activate_prepared_release_uses_owner_file_context_and_existing_restart_path(deploy_env):
    e = deploy_env
    assert e.run('prepare', e.sha)[0] == 0
    e.trust("VERSION = 'a'\n")
    home = e.tmp / 'owner-home'
    config = home / '.config' / 'agentporter'
    config.mkdir(parents=True)
    (config / 'secrets.env').write_text('AGENTPORTER_API_KEY=fixture-only-file-key\n')
    (config / 'secrets.env').chmod(0o600)
    code, out = e.run('activate', e.sha, HOME=str(home), AGENTPORTER_API_KEY='wrong-inherited-fixture',
                      AGENTPORTER_CONFIG_DIR='/wrong-gateway-config', AGENTPORTER_PROFILE='production',
                      FAKE_REQUIRE_CLEAN_GATEWAY_ENV='1')
    assert code == 0, out
    assert e.restarts() == ['--user restart agentporter.service']
    assert os.readlink(e.root / 'current') == 'releases/' + e.sha
    assert '--config-dir ' + str(config) in Path(str(e.log) + '.python').read_text()


@pytest.mark.parametrize('command', ['prepare', 'activate'])
def test_new_release_commands_keep_full_sha_and_trigger_gates(deploy_env, command):
    e = deploy_env
    code, out = e.run(command, 'main')
    assert code == 2 and '40-hex' in out
    Path(e.env['FAKE_TRIGGERS']).write_text('agentporter-activate.path enabled enabled\n')
    code, out = e.run(command, e.sha)
    assert code == 2 and 'path-triggered' in out and e.restarts() == []


def test_activate_refuses_unit_drift_and_unsealed_prepared_tree(deploy_env):
    e = deploy_env
    assert e.run('prepare', e.sha)[0] == 0
    code, out = e.run('activate', e.sha, FAKE_EXEC='/mutable/repo/.venv/bin/agentporter')
    assert code == 2 and 'config drift' in out
    (e.root / 'releases' / e.sha / 'src').chmod(0o755)
    code, out = e.run('activate', e.sha)
    assert code == 2 and 'sealed modes' in out and e.restarts() == []



@pytest.mark.parametrize('stop_rc', ['0', '1'])
def test_prepared_activation_failure_holds_without_restarting_old_release(deploy_env, stop_rc):
    e = deploy_env
    e.trust("VERSION = 'a'\n")
    assert e.run('deploy', e.sha)[0] == 0
    next_sha = _commit(e.repo, "VERSION = 'b'\n")
    assert e.run('prepare', next_sha)[0] == 0
    home = e.tmp / 'owner-home'
    config = home / '.config' / 'agentporter'
    config.mkdir(parents=True)
    (config / 'secrets.env').write_text('AGENTPORTER_API_KEY=fixture-only-file-key\n')
    (config / 'secrets.env').chmod(0o600)
    code, out = e.run('activate', next_sha, '--wait', '0', HOME=str(home), FAKE_STOP_RC=stop_rc)
    assert code == 1 and 'restore reviewed unit/config/release pair before restart' in out
    assert ('STOP FAILED' in out) is (stop_rc == '1')
    assert e.restarts() == ['--user restart agentporter.service'] * 2
    assert e.calls().count('--user stop agentporter.service') == 1
    assert os.readlink(e.root / 'current') == 'releases/' + next_sha
    assert os.readlink(e.root / 'previous') == 'releases/' + e.sha



def test_activate_rejects_resealed_package_fingerprint_drift_before_mutation(deploy_env):
    e = deploy_env
    assert e.run('prepare', e.sha)[0] == 0
    package = next((e.root / 'releases' / e.sha / 'venv').glob('lib/python3*/site-packages/agentporter'))
    (package / '__init__.py').chmod(0o644)
    (package / '__init__.py').write_text("VERSION = 'unreviewed'\n")
    (package / '__init__.py').chmod(0o444)
    code, out = e.run('activate', e.sha)
    assert code == 2 and 'fingerprint differs' in out
    assert e.restarts() == [] and not (e.root / 'current').exists()
