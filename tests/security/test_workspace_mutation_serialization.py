"""Public mutations must not race private job finalization."""
from pathlib import Path
import pytest
from agentporter.sandbox.workspace_transactions import WorkspaceTransaction
from agentporter.sandbox.bubblewrap import BubblewrapSandbox
from agentporter.tools.files import create_file_tools
from agentporter.tools.git import create_git_tools
from agentporter.workspaces.registry import WorkspaceRegistry

pytestmark = pytest.mark.skipif(not Path('/opt/agentporter-bcc/bin/bwrap').is_file(), reason='BCC transaction integration requires installed sandbox')


def setup(tmp_path):
    root = tmp_path / 'project'
    root.mkdir()
    state = tmp_path / 'state'
    registry = WorkspaceRegistry({'project': {'path': str(root), 'writable': True}})
    return root, state, registry


def test_file_write_cannot_race_active_transaction(tmp_path):
    root, state, registry = setup(tmp_path)
    tools = create_file_tools(registry, mutation_state_dir=state / 'workspace-transactions')
    transaction = WorkspaceTransaction(root, state / 'workspace-transactions')
    try:
        with pytest.raises(PermissionError):
            tools[3]('project', 'ordinary', 'outside edit')
        assert not (root / 'ordinary').exists()
    finally:
        transaction.close()
    tools[3]('project', 'ordinary', 'outside edit')
    assert (root / 'ordinary').read_text() == 'outside edit'


def test_trusted_git_write_cannot_race_active_transaction(tmp_path):
    root, state, registry = setup(tmp_path)
    sandbox = BubblewrapSandbox(state, transactional_writes=True)
    tools = create_git_tools(registry, sandbox)
    transaction = WorkspaceTransaction(root, state / 'workspace-transactions')
    try:
        with pytest.raises(PermissionError):
            tools.git_checkout('project', 'new-branch', create=True)
    finally:
        transaction.close()


@pytest.mark.parametrize('index, arguments', [
    (3, ('ordinary', 'edit')),
    (4, ('not-a-patch',)),
    (5, ('new-directory',)),
    (6, ('ordinary', 'moved')),
    (7, ('ordinary',)),
])
def test_pending_publication_blocks_every_file_mutation(tmp_path, index, arguments):
    from agentporter.resources import ResourceCleanupError
    root, state, registry = setup(tmp_path)
    tools = create_file_tools(registry, mutation_state_dir=state / 'workspace-transactions')
    transaction = WorkspaceTransaction(root, state / 'workspace-transactions')
    pending = transaction._pending
    pending.write_text('{"synthetic":true}')
    transaction.close()
    try:
        with pytest.raises(ResourceCleanupError):
            tools[index]('project', *arguments)
    finally:
        pending.unlink()


def test_enabled_server_requires_resource_supervision(tmp_path):
    from agentporter.config import Config
    from agentporter.server import build_mcp_server
    cfg = Config(config_dir=tmp_path / 'cfg', state_dir=tmp_path / 'state', cache_dir=tmp_path / 'cache')
    cfg.sandbox.workspace_transactions = True
    with pytest.raises(PermissionError, match='resource supervision'):
        build_mcp_server(cfg)
