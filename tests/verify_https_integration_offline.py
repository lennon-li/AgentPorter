"""Isolated offline integration smoke for staged HTTPS execution routing."""
from __future__ import annotations

import sys, types, tempfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

def stub_package(name, path):
    module = types.ModuleType(name)
    module.__path__ = [str(path)]
    sys.modules[name] = module

stub_package("agentporter.tools", ROOT / "src/agentporter/tools")
stub_package("agentporter.workspaces", ROOT / "src/agentporter/workspaces")
stub_package("agentporter.sandbox", ROOT / "src/agentporter/sandbox")

registry_mod = types.ModuleType("agentporter.workspaces.registry")
registry_mod.WorkspaceRegistry = object
sys.modules[registry_mod.__name__] = registry_mod
sandbox_mod = types.ModuleType("agentporter.sandbox.bubblewrap")
sandbox_mod.BubblewrapSandbox = object
sys.modules[sandbox_mod.__name__] = sandbox_mod

from agentporter.scoped_https import ScopedPublicHTTPS, ScopedPublicHTTPSPolicy
from agentporter.tools.execution import create_execution_tools
from agentporter.tools.jobs import JobManager
from agentporter.tools import jobs as job_module

with tempfile.TemporaryDirectory(prefix="https_integration_") as td:
    tmp = Path(td)
    cfg = tmp / "operator"
    cfg.mkdir(mode=0o700)
    (cfg / "public-https.yaml").write_text(
        "version: 1\nworkspaces:\n  cranary:\n    hosts: [api.github.com, cran.r-project.org, cran-archive.r-project.org, bioconductor.org]\n    methods: [GET, HEAD]\n    max_response_bytes: 262144\n    timeout_seconds: 15\n"
    )
    (cfg / "public-https.yaml").chmod(0o600)
    policy = ScopedPublicHTTPSPolicy(cfg)
    broker = ScopedPublicHTTPS(policy)
    from agentporter import scoped_https as scoped_https_module
    scoped_https_module.subprocess.run = Mock(
        return_value=SimpleNamespace(returncode=0, stdout='{"ok":true}', stderr="")
    )
    workspace_root = tmp / "workspace"
    workspace_root.mkdir()
    ws = SimpleNamespace(path=str(workspace_root), writable=True, allow_execute=True)
    reg = SimpleNamespace(get=lambda ident: ws if ident == "cranary" else (_ for _ in ()).throw(KeyError(ident)))
    sandbox = Mock()
    sandbox.run.return_value = {"exit_code":0,"stdout":"offline-ok","stderr":""}
    sandbox.clamp_timeout.side_effect=lambda n:min(n,900)
    from agentporter.tools.jobs import JobManager
    jobs = JobManager(tmp / 'job-state')
    jobs.start_scoped_https_job = Mock()
    jobs.start_scoped_https_job.return_value="job_fixed"
    er, es = create_execution_tools(reg,sandbox,jobs,scoped_https=broker)

    approved=["curl","-fsS","https://api.github.com/repos/ropensci/software-review/issues/1"]
    assert er("cranary", approved, network_access=True)["exit_code"] == 0
    scoped_https_module.subprocess.run.assert_called_once()
    sandbox.run.assert_not_called()

    assert er("cranary", ["echo","offline"],network_access=False)["stdout"] == "offline-ok"
    sandbox.run.assert_called_once()
    assert es("cranary",approved,network_access=True)["job_id"] == "job_fixed"
    args=jobs.start_scoped_https_job.call_args.kwargs
    assert args["workspace_id"]=="cranary" and args["method"]=="GET"
    assert args["timeout_seconds"]==15
    sandbox.build_bwrap_args.assert_not_called()

    for argv in (["bash","-c","curl https://api.github.com/"],
                 ["curl","-fsS","https://example.com/"]):
        try:er("cranary",argv,network_access=True)
        except PermissionError:pass
        else:raise AssertionError(f"Unapproved outbound argv: {argv}")
    try:er("other",approved,network_access=True)
    except KeyError:pass
    else:raise AssertionError("Unregistered workspace could use scoped HTTPS")
    try:es("cranary",["curl","-fsS","https://example.com/"],network_access=True)
    except PermissionError:pass
    else:raise AssertionError("Unapproved async outbound request")
    assert jobs.start_scoped_https_job.call_count==1

    # Verify background entrypoint cannot launch caller-selected code and
    # strips credentials even if the service's host env contains them.
    job_manager = JobManager(tmp / "state")
    original_popen = job_module.subprocess.Popen
    launches = []
    def capture(cmd,**kwargs):
        launches.append((cmd,kwargs))
        raise RuntimeError("capture-only (no worker execution)")
    job_module.subprocess.Popen = capture
    try:
        try:
            job_manager.start_scoped_https_job(
                "cranary",str(workspace_root),str(cfg),"GET",approved[2],15)
        except RuntimeError as exc:
            assert "capture-only" in str(exc)
        else:raise AssertionError("Didn't intercept worker")
    finally:
        job_module.subprocess.Popen = original_popen
    assert len(launches)==1
    cmd,kwargs=launches[0]
    assert cmd[1:4]==["-I","-m","agentporter.scoped_https_worker"]
    assert kwargs["env"] == {
        "PATH":"/usr/bin:/bin","LANG":"C.UTF-8",
        "LC_ALL":"C.UTF-8","HOME":"/nonexistent",
    }
    assert kwargs["process_group"]==0
    assert kwargs.get("shell") is None

print("PASS: scoped exec_run/exec_start routing, offline regression, fake async launcher")
