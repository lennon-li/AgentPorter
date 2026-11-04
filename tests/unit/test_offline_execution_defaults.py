"""Generic REST execution cannot silently enable host networking."""

from agentporter.rest.schemas import ExecRunRequest, ExecStartRequest


def test_rest_defaults_offline():
    assert ExecRunRequest(argv=["true"]).network_access is False
    assert ExecStartRequest(argv=["true"]).network_access is False
