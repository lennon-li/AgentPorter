"""Qman advisory integration through the real broker and native JSON boundary."""
import json
import logging
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock
import pytest
from agentporter import qman
from agentporter.agents.broker import AgentBroker
from agentporter.tools.agents import create_agent_tools


def payload(remaining=75, fresh=True, bound=True):
    return {"mode": "consultation", "execution_authorized": False, "dispatch_enabled": False,
      "resources": [{"identity_bound": bound, "windows": [{"bucket_id": "codex", "window": "primary",
      "duration_minutes": 300, "remaining_percent_at_observation": remaining,
      "remaining_percent_current": remaining if fresh and bound else None,
      "observation_fresh": fresh, "evidence_status": "native_codex_bound" if bound else "native_client_report_unverified"}]}]}


@pytest.fixture
def native(tmp_path, monkeypatch):
    db=tmp_path/"qman.db"
    db.write_bytes(b"fixture")
    db.chmod(0o600)
    monkeypatch.setattr(qman, "DATABASE", db)
    root=tmp_path/"qman-source"
    (root/"src").mkdir(parents=True)
    interpreter=root/".venv/bin/python"
    interpreter.parent.mkdir(parents=True)
    interpreter.write_bytes(b"synthetic interpreter")
    monkeypatch.setattr(qman, "ROOT", root)
    monkeypatch.setattr(qman, "PYTHON", interpreter)
    return db


@pytest.fixture
def registry(tmp_path):
    safe=tmp_path/"registered-workspace"
    safe.mkdir()
    return SimpleNamespace(list_all=lambda: [{"path": str(safe)}])


@pytest.mark.parametrize("provider,profile,model", [("bad",None,None),([],None,None),("all","x;id",None),("all",None,"$(id)")])
def test_invalid_scope_no_subprocess(monkeypatch,provider,profile,model):
    run=Mock()
    monkeypatch.setattr(qman, "_read", run)
    assert qman.qman_consult(provider,profile,model)["error"] == "invalid_scope"
    run.assert_not_called()


def test_exact_json_and_fixed_argv(native,registry,monkeypatch):
    raw=payload()
    raw["resources"][0].update({"provider":"codex", "quota_state":"headroom_reported", "quota_reason":"quota_only_not_execution_authorization", "principal":"PRIVATE"})
    reader=Mock(return_value=json.dumps(raw).encode())
    monkeypatch.setattr(qman,"_read",reader)
    result=qman.qman_consult("codex","jax","gpt-6.1-sol",workspace_registry=registry)
    assert result["execution_authorized"] is False and result["dispatch_enabled"] is False
    assert result["resources"][0]["provider"] == "codex"
    assert "principal" not in json.dumps(result) and "profile" not in result["resources"][0]
    argv=reader.call_args.args[0]
    assert "collect" not in argv and "--db" in argv and "consult" in argv
    assert argv[-2:] == ["--profile=jax","--model=gpt-6.1-sol"]


@pytest.mark.parametrize("raw", [b"not json", b"[]", b'{"mode":"consultation","resources":[],"execution_authorized":true,"dispatch_enabled":false}', b"NaN"])
def test_bad_json_controlled(native,registry,monkeypatch,raw):
    monkeypatch.setattr(qman,"_read",lambda _:raw)
    assert qman.qman_consult(workspace_registry=registry)["mode"] == "consultation_unavailable"


def test_owner_permissions_preserved(native,registry,monkeypatch):
    native.chmod(0o644)
    reader=Mock()
    monkeypatch.setattr(qman,"_read",reader)
    assert qman.qman_consult(workspace_registry=registry)["error"] == "owner_only_database_unavailable"
    assert native.stat().st_mode & 0o777 == 0o644
    reader.assert_not_called()


@pytest.fixture
def gateway(tmp_path,monkeypatch):
    monkeypatch.setenv("QMAN_PREFLIGHT_MODE","shadow")
    ws=SimpleNamespace(path=str(tmp_path),writable=True,allow_agent_dispatch=True)
    jobs=Mock()
    jobs.start_confined_agent_job.return_value="job-unit"
    broker=AgentBroker(SimpleNamespace(get=lambda _:ws),jobs,config_dir=tmp_path)
    adapter=broker.adapters["jax"]
    adapter.executable_override="/usr/bin/false"
    monkeypatch.setattr(adapter,"detect",lambda:{"is_installed":True,"configured_model":"gpt-6.1-sol","provider":"OpenAI"})
    return broker,ws,jobs


@pytest.mark.parametrize("observation",[payload(),payload(fresh=False),payload(bound=False),payload(remaining=0),{"mode":"consultation_unavailable","error":"qman_unavailable"},payload(remaining=None,bound=False)])
def test_real_tool_broker_path_keeps_routing(gateway,monkeypatch,caplog,observation):
    broker,_,jobs=gateway
    read=Mock(return_value=observation)
    monkeypatch.setattr(qman,"qman_consult",read)
    _,dispatch=create_agent_tools(broker)
    with caplog.at_level(logging.INFO,logger="agentporter.qman"):
        result=broker.dispatch_agent(agent="jax",task="PRIVATE PROMPT",workspace_id="unit")
    read.assert_called_once_with("codex","jax",model="gpt-6.1-sol",workspace_registry=broker.workspace_registry)
    assert result["worker_cli"] == "codex"
    assert jobs.start_confined_agent_job.call_args.kwargs["agent"] == "jax"
    assert "PRIVATE PROMPT" not in caplog.text
    event=json.loads(caplog.records[-1].message)
    assert event["would_change_decision"] is None
    assert event["runtime_outcome"] == "launch_accepted"
    assert event["job_id"] == "job-unit"


def test_off_default_no_consult(gateway,monkeypatch):
    broker,_,_=gateway
    monkeypatch.delenv("QMAN_PREFLIGHT_MODE")
    read=Mock()
    monkeypatch.setattr(qman,"qman_consult",read)
    broker.dispatch_agent("jax","task","unit")
    read.assert_not_called()


@pytest.mark.parametrize("denial",["workspace","publication","model","unconfined_readonly"])
def test_existing_gates_cannot_be_bypassed_by_headroom(gateway,monkeypatch,denial):
    broker,ws,jobs=gateway
    read=Mock(return_value=payload())
    monkeypatch.setattr(qman,"qman_consult",read)
    args={}
    agent="jax"
    if denial=="workspace": ws.allow_agent_dispatch=False
    elif denial=="publication": args["allow_push"]=True
    elif denial=="model": args["model"]="gpt-5.6"
    else:
        agent="agy"
        monkeypatch.setattr(broker.adapters["agy"],"detect",lambda:{"is_installed":True})
    with pytest.raises((PermissionError,ValueError)):
        broker.dispatch_agent(agent,"task","unit",**args)
    jobs.start_confined_agent_job.assert_not_called()
    read.assert_not_called()


def test_registration_readonly_metadata(tmp_path,monkeypatch):
    from agentporter.config import Config
    from agentporter.server import build_mcp_server
    monkeypatch.setenv("AGENTPORTER_API_KEY","unit-only-key")
    config=Config(config_dir=tmp_path/"config",state_dir=tmp_path/"state")
    mcp,_=build_mcp_server(config)
    tool={t.name:t for t in mcp._tool_manager.list_tools()}["qman_consult"]
    assert tool.annotations.read_only_hint is True
    assert tool.annotations.destructive_hint is False


def test_public_dispatch_still_refuses_unconfined_worker(gateway, monkeypatch):
    broker, _, jobs = gateway
    read = Mock(return_value=payload())
    monkeypatch.setattr(qman, "qman_consult", read)
    _, dispatch = create_agent_tools(broker)
    with pytest.raises(PermissionError, match="confinement"):
        dispatch(agent="jax", task="task", workspace_id="unit")
    jobs.start_confined_agent_job.assert_not_called()
    jobs.start_raw_job.assert_not_called()
    read.assert_not_called()

@pytest.mark.parametrize("relation", ["equal", "ancestor", "descendant", "symlink"])
def test_registered_workspace_overlap_refuses_before_read(native, tmp_path, monkeypatch, relation):
    root=qman.ROOT
    if relation == "equal":
        workspace=root
    elif relation == "ancestor":
        workspace=root.parent
    elif relation == "descendant":
        workspace=root/"src"/"project"
        workspace.mkdir()
    else:
        workspace=tmp_path/"workspace-link"
        workspace.symlink_to(root, target_is_directory=True)
    registry=SimpleNamespace(list_all=lambda: [{"path":str(workspace)}])
    reader=Mock()
    monkeypatch.setattr(qman,"_read",reader)
    assert qman.qman_consult(workspace_registry=registry)["error"] == "qman_source_overlaps_workspace"
    reader.assert_not_called()


@pytest.mark.parametrize("registry", [None, SimpleNamespace(list_all=lambda: []),
    SimpleNamespace(list_all=lambda: [{"path":""}]),
    SimpleNamespace(list_all=lambda: [{"path":"/path/that/does/not/exist"}])])
def test_missing_or_invalid_registry_refuses_before_read(native, monkeypatch, registry):
    reader=Mock()
    monkeypatch.setattr(qman,"_read",reader)
    assert qman.qman_consult(workspace_registry=registry)["mode"] == "consultation_unavailable"
    reader.assert_not_called()


def test_all_registered_workspaces_are_checked(native, tmp_path, monkeypatch):
    safe=tmp_path/"safe-workspace"
    safe.mkdir()
    registry=SimpleNamespace(list_all=lambda: [{"path":str(safe)}, {"path":str(qman.ROOT/"src")}])
    reader=Mock()
    monkeypatch.setattr(qman,"_read",reader)
    assert qman.qman_consult(workspace_registry=registry)["error"] == "qman_source_overlaps_workspace"
    reader.assert_not_called()


def test_sanitized_projection_filters_private_malformed_and_nonfinite_values():
    raw={"mode":"consultation", "execution_authorized":False, "dispatch_enabled":False,
      "as_of_utc_epoch":float("nan"), "principal":"billing-secret", "prompt":"PRIVATE",
      "resources":[{"provider":"codex", "profile":"private-profile", "identity_digest":"secret",
       "quota_state":"headroom_reported", "quota_reason":"quota_only_not_execution_authorization",
       "windows":[{"window":"primary", "remaining_percent_current":50,
         "observed_at_utc_epoch":float("inf"), "observation_fresh":True,
         "identity_digest":"secret", "principal":"billing-secret", "transcript":"private"},
         "not-a-window"]}]}
    result=qman._bounded_projection(raw)
    encoded=json.dumps(result,allow_nan=False)
    assert result["execution_authorized"] is False and result["dispatch_enabled"] is False
    assert result["resources"][0]["quota_state"] == "headroom_reported"
    assert result["resources"][0]["windows"][0]["remaining_percent_current"] == 50
    assert "observed_at_utc_epoch" not in result["resources"][0]["windows"][0]
    for private in ("billing-secret","PRIVATE","private-profile","identity_digest","transcript"):
        assert private not in encoded


def test_option_like_identifiers_rejected():
    assert not qman._identifier("--help")
    assert not qman._identifier("-profile")
    assert qman._identifier("jax")


def test_read_rejects_timeout_oversize_and_nonzero(monkeypatch, tmp_path):
    import sys
    monkeypatch.setattr(qman,"ROOT",tmp_path)
    monkeypatch.setattr(qman,"TIMEOUT",0.05)
    with pytest.raises(TimeoutError):
        qman._read([sys.executable,"-c","import time; time.sleep(2)"])
    monkeypatch.setattr(qman,"TIMEOUT",2)
    monkeypatch.setattr(qman,"MAX_BYTES",32)
    with pytest.raises(ValueError):
        qman._read([sys.executable,"-c","print('x'*100)"])
    with pytest.raises(RuntimeError):
        qman._read([sys.executable,"-c","raise SystemExit(7)"])


def test_read_timeout_kills_process_group_descendant(tmp_path, monkeypatch):
    import sys
    monkeypatch.setattr(qman,"ROOT",tmp_path)
    marker=tmp_path/"descendant-survived"
    code=("import subprocess,sys; "
          f"subprocess.Popen([sys.executable,'-c',\"import time; time.sleep(.4); open('{marker}','w').write('alive')\"]); "
          "print('started',flush=True); import time; time.sleep(2)")
    monkeypatch.setattr(qman,"TIMEOUT",0.1)
    with pytest.raises(TimeoutError):
        qman._read([sys.executable,"-c",code])
    import time
    time.sleep(0.5)
    assert not marker.exists()


def test_shadow_overlap_refuses_qman_but_preserves_dispatch_advisory(native, monkeypatch, tmp_path):
    monkeypatch.setenv("QMAN_PREFLIGHT_MODE", "shadow")
    workspace=qman.ROOT/"src"
    registry=SimpleNamespace(list_all=lambda: [{"path":str(workspace)}])
    reader=Mock()
    monkeypatch.setattr(qman,"_read",reader)
    event=qman.shadow_consult("jax","gpt-6.1-sol",registry)
    assert event["consultation_outcome"] == "unavailable"
    reader.assert_not_called()


def test_shadow_unexpected_consult_exception_is_advisory_and_does_not_log_private_text(gateway, monkeypatch, caplog):
    broker,_,jobs=gateway
    marker = "private-marker-7f9c"
    def fail(*args, **kwargs):
        raise RuntimeError(marker)
    monkeypatch.setattr(qman,"qman_consult",fail)
    result=broker.dispatch_agent(agent="jax",task="bounded task",workspace_id="unit")
    assert result["job_id"] == "job-unit"
    jobs.start_confined_agent_job.assert_called_once()
    assert marker not in caplog.text
    assert all(marker not in repr(record.args) for record in caplog.records)


def test_shadow_logging_failure_is_advisory(gateway, monkeypatch):
    broker,_,jobs=gateway
    def fail(*args, **kwargs):
        raise RuntimeError("synthetic consultation failure")
    def fail_logging(*args, **kwargs):
        raise OSError("synthetic logging failure")
    monkeypatch.setattr(qman,"qman_consult",fail)
    monkeypatch.setattr(qman.logger,"warning",fail_logging)

    event = qman.shadow_consult("jax", "gpt-6.1-sol")
    assert event["consultation_outcome"] == "unavailable"
    result=broker.dispatch_agent(agent="jax",task="bounded task",workspace_id="unit")
    assert result["job_id"] == "job-unit"
    jobs.start_confined_agent_job.assert_called_once()
