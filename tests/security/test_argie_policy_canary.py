"""Synthetic tests: never launch providers or read real authentication."""
import importlib.util
import json
from pathlib import Path
import pytest

spec = importlib.util.spec_from_file_location('argie_canary', Path(__file__).resolve().parents[2] / 'scripts/verify-argie-policy-sandbox.py')
canary = importlib.util.module_from_spec(spec)
spec.loader.exec_module(canary)


def test_fixture_contains_only_nonsecret_canaries_and_alias_cases(tmp_path):
    home, workspace, shared, paths = canary.fixture(tmp_path)
    assert not (home / canary.TOKEN).exists()
    assert (shared / 'Toolbox/claude-skills/canary/SKILL.md').read_text().startswith('NONSECRET_POLICY_CANARY_')
    assert (workspace / 'config-alias').readlink() == Path('/home/worker/.config/policy-canary.txt')
    assert '/workspace/../home/worker/.config/policy-canary.txt' in paths
    assert '/workspace/gemini-dir/../.config/policy-canary.txt' in paths
    assert '/workspace-other/policy-canary.txt' in paths
    policy = json.loads((tmp_path / 'policy.json').read_text())
    assert policy['allow'] == ['read_file(/workspace)', 'read_file(/opt/agentporter/shared/obsidian)']
    assert 'command(*)' in policy['deny']
    assert all(path.name != 'antigravity-oauth-token' for path in tmp_path.rglob('*'))


def test_private_reader_rejects_symlink_public_and_fifo(tmp_path):
    private = tmp_path / 'private'
    canary.private_write(private, b'synthetic')
    assert canary.read_private(private) == b'synthetic'
    alias = tmp_path / 'alias'
    alias.symlink_to(private)
    with pytest.raises(OSError):
        canary.read_private(alias)
    private.chmod(0o644)
    with pytest.raises(ValueError):
        canary.read_private(private)
    fifo = tmp_path / 'fifo'
    import os
    os.mkfifo(fifo, 0o600)
    with pytest.raises(ValueError):
        canary.read_private(fifo)
