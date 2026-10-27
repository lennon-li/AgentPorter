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
    return db


@pytest.mark.parametrize("provider,profile,model", [("bad",None,None),([],None,None),("all","x;id",None),("all",None,"$(id)")])
def test_invalid_scope_no_subprocess(monkeypatch,provider,profile,model):
    run=Mock()
    monkeypatch.setattr(qman, "_read", run)
    assert qman.qman_consult(provider,profile,model)["error"] == "invalid_scope"
    run.assert_not_called()


def test_exact_json_and_fixed_argv(native,monkeypatch):
    expected=payload()
    reader=Mock(return_value=json.dumps(expected).encode())
    monkeypatch.setattr(qman,"_read",reader)
    assert qman.qman_consult("codex","jax","gpt-6.1-sol") == expected
    argv=reader.call_args.args[0]
    assert "collect" not in argv and "--db" in argv and "consult" in argv
    assert argv[-4:] == ["--profile","jax","--model","gpt-6.1-sol"]


@pytest.mark.parametrize("raw", [b"not json", b"[]", b'{"mode":"consultation","resources":[],"execution_authorized":true,"dispatch_enabled":false}', b"NaN"])
def test_bad_json_controlled(native,monkeypatch,raw):
    monkeypatch.setattr(qman,"_read",lambda _:raw)
    assert qman.qman_consult()["mode"] == "consultation_unavailable"


def test_owner_permissions_preserved(native,monkeypatch):
    native.chmod(0o644)
    reader=Mock()
    monkeypatch.setattr(qman,"_read",reader)
    assert qman.qman_consult()["error"] == "owner_only_database_unavailable"
    assert native.stat().st_mode & 0o777 == 0o644
    reader.assert_not_called()


@pytest.fixture
def gateway(tmp_path,monkeypatch):
    monkeypatch.setenv("QMAN_PREFLIGHT_MODE","shadow")
    ws=SimpleNamespace(path=str(tmp_path),writable=True,allow_agent_dispatch=True)
    jobs=Mock()
    jobs.start_raw_job.return_value="job-unit"
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
        result=dispatch(agent="jax",task="PRIVATE PROMPT",workspace_id="unit")
    read.assert_called_once_with("codex","jax",model="gpt-6.1-sol")
    assert result["selected_agent"] == "jax"
    assert jobs.start_raw_job.call_args.kwargs["agent"] == "jax"
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
    jobs.start_raw_job.assert_not_called()
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
