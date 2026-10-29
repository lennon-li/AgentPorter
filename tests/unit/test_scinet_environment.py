from unittest.mock import patch
import pytest
from agentporter.config import Config, ScinetSettings


def test_explicit_service_environment_grants_only_registered_workspace():
    config = Config.__new__(Config)
    config.scinet = ScinetSettings()
    config.workspaces = {"cranary": {}, "other": {}}
    with patch.dict("os.environ", {
        "AGENTPORTER_SCINET_HOST": "trillium-gpu.alliancecan.ca",
        "AGENTPORTER_SCINET_USER": "operator",
        "AGENTPORTER_SCINET_CONTROL_SOCKET": "/home/operator/.ssh/cm-operator@trillium-gpu.alliancecan.ca:22",
        "AGENTPORTER_SCINET_MACHINE": "asgard",
        "AGENTPORTER_SCINET_WORKSPACE": "cranary",
    }, clear=True):
        config._load_scinet_environment()
    assert config.workspaces["cranary"]["allow_scinet_diagnostic"] is True
    assert "allow_scinet_diagnostic" not in config.workspaces["other"]
    assert config.scinet.machine == "asgard"


def test_service_grant_cannot_create_unregistered_workspace():
    config = Config.__new__(Config)
    config.scinet = ScinetSettings()
    config.workspaces = {}
    with patch.dict("os.environ", {"AGENTPORTER_SCINET_WORKSPACE": "missing"}, clear=True):
        with pytest.raises(ValueError):
            config._load_scinet_environment()


def test_without_service_override_no_workspace_is_granted():
    config = Config.__new__(Config)
    config.scinet = ScinetSettings()
    config.workspaces = {"cranary": {}}
    with patch.dict("os.environ", {}, clear=True):
        config._load_scinet_environment()
    assert "allow_scinet_diagnostic" not in config.workspaces["cranary"]
