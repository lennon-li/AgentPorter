"""Offline confinement probes of the frozen native CLI; no real credentials."""
import json
import os
from pathlib import Path

import pytest

from tests.security.test_development_runtime import runtime_factory, save

PAYLOAD = os.environ.get('BCC_TEST_SHARED_CODEX_ROOT')
pytestmark = pytest.mark.skipif(not PAYLOAD, reason='Explicit frozen BCC CLI payload required')


def provision(runtime_factory):
    runtime, config, path, workspace, _ = runtime_factory()
    binary = Path(PAYLOAD)/'codex'
    helper = Path(PAYLOAD)/'codex-code-mode-host'
    spec = config['workers']['codex_impl']
    spec.update(executable=str(binary), code_mode_host=str(helper))
    save(config, path)
    return runtime, config, runtime._spec('codex_impl', config), workspace


def test_frozen_codex_and_matching_helper_pass_os_confinement_probes(runtime_factory):
    runtime, config, spec, _ = provision(runtime_factory)
    runtime._probe('codex_impl', config, spec)
    evidence = runtime._evidence['codex_impl']
    assert '0.167.2' in evidence['cli_version']
    assert set(evidence['verified_modes']) == {'read-only', 'writable'}


def test_frozen_codex_does_not_add_ambient_mcp_tools(runtime_factory):
    runtime, config, spec, workspace = provision(runtime_factory)
    launch = runtime._build('codex_impl', config, spec, workspace, False,
                            [spec['executable'], 'mcp', 'list', '--json'], probe=True)
    try:
        result = runtime._run_probe(launch.command, launch.pass_fds)
        assert result.returncode == 0, result.stderr
        assert json.loads(result.stdout) == []
    finally:
        launch.cleanup()
