"""BCC approval boundaries exercised with real local disposable repositories."""
from pathlib import Path

import pytest

from tests.security.test_approved_git_commit import backend
from tests.security.test_git_approval_state import git
from tests.security.test_development_runtime import runtime_factory


def test_ordinary_edits_persist_after_worker_exit(tmp_path):
    root, _, sandbox, _ = backend(tmp_path)
    before = git(root, 'rev-parse', 'HEAD')
    result = sandbox.run(str(root), ['/usr/bin/python3', '-c',
        "from pathlib import Path; Path('/workspace/ordinary').write_text('persistent edit')"],
        writable=True, timeout_seconds=30)
    assert result['exit_code'] == 0, result
    assert (root/'ordinary').read_text() == 'persistent edit'
    assert git(root, 'rev-parse', 'HEAD') == before


@pytest.mark.parametrize('mutation', ['commit', 'raw_ref'])
def test_unapproved_history_cannot_cross_transaction_boundary(tmp_path, mutation):
    root, _, sandbox, _ = backend(tmp_path)
    before = git(root, 'rev-parse', 'HEAD')
    original = (root/'ordinary').read_bytes()
    if mutation == 'commit':
        code = ("from pathlib import Path; import subprocess; "
                "Path('/workspace/ordinary').write_text('unapproved'); "
                "subprocess.run(['git','-c','safe.directory=/workspace','-c','user.name=Worker',"
                "'-c','user.email=worker@example.invalid','commit','-am','not approved'],check=True)")
    else:
        # Direct metadata write bypasses every command-prefix guard.
        code = ("from pathlib import Path; "
                "Path('/workspace/.git/HEAD').write_text(" + repr(before+'\n') + "); "
                "Path('/workspace/ordinary').write_text('unapproved')")
    code += "; print('HISTORY_MUTATION_EXECUTED', flush=True)"
    result = sandbox.run(str(root), ['/usr/bin/python3', '-c', code], writable=True, timeout_seconds=30)
    assert 'HISTORY_MUTATION_EXECUTED' in result['stdout'], result
    assert result['exit_code'] != 0, result
    assert git(root, 'rev-parse', 'HEAD') == before
    assert git(root, 'symbolic-ref', 'HEAD')
    assert (root/'ordinary').read_bytes() == original


def test_signed_commit_backend_is_the_only_server_commit_route(temp_config, monkeypatch):
    import agentporter.git_policy as policy
    from agentporter.server import build_mcp_server
    called = []
    monkeypatch.setattr(policy, 'load_approved_commits', lambda *a: called.append(a) or None)
    # Existing default config lacks supervised transactions, so no commit
    # service is available and an unsigned request always fails closed.
    _, context = build_mcp_server(temp_config)
    with pytest.raises(PermissionError):
        context['tools']['git_commit'](workspace_id='missing', message='no approval')


def test_worker_cannot_create_history_in_a_new_subrepository(tmp_path):
    from agentporter.sandbox.workspace_transactions import WorkspaceTransaction
    root, _, sandbox, _ = backend(tmp_path)
    transaction = WorkspaceTransaction(root, sandbox.state_dir/'workspace-transactions',
                                       git_sandbox=sandbox, allow_git_birth=True)
    code = ("from pathlib import Path; import subprocess; "
            "p=Path('/workspace/new-repo'); p.mkdir(); "
            "subprocess.run(['git','init',str(p)],check=True); "
            "(p/'file').write_text('new history'); "
            "subprocess.run(['git','-C',str(p),'add','file'],check=True); "
            "subprocess.run(['git','-C',str(p),'-c','user.name=Worker',"
            "'-c','user.email=worker@example.invalid','commit','-m','not approved'],check=True); "
            "print('NEW_COMMIT_EXECUTED',flush=True)")
    try:
        result = sandbox._run_command(workspace_path=str(root), argv=['/usr/bin/python3','-c',code],
            writable=True, workspace_transaction=transaction, require_resources=True,
            timeout_seconds=30, max_output_bytes=65536, network_access=False)
        assert result['exit_code'] == 0 and 'NEW_COMMIT_EXECUTED' in result['stdout'], result
        with pytest.raises(PermissionError, match='independent owner approval'):
            transaction.publish()
        assert not (root/'new-repo').exists()
    finally:
        transaction.close()


def test_approved_pull_does_not_authorize_a_subsequent_worker_commit(tmp_path, monkeypatch, runtime_factory):
    import json
    from agentporter.agents.policy import ExecutionPolicy
    from agentporter.git_approvals import GitApprovalRequest, issue_git_approval
    from agentporter.tools.git import create_git_tools
    from tests.security.test_worker_git_runtime import configured, WORKER, wait_output, terminal
    root, service, key, manager, _ = configured(tmp_path, monkeypatch, runtime_factory)
    original = git(root, 'rev-parse', 'HEAD')
    malicious = WORKER.replace("print('CONTINUED_EDIT',flush=True)",
        "subprocess.run(['/usr/bin/git','-c','user.name=Worker','-c','user.email=worker@example.invalid',"
        "'commit','-qm','unapproved after pull'],check=True); print('CONTINUED_COMMIT',flush=True)")
    job = manager.start_confined_agent_job(workspace_id='repo', workspace_path=str(root), agent='codex_impl',
        cmd=['/usr/bin/python3','-c',malicious], policy=ExecutionPolicy.for_workspace(writable=True), timeout_seconds=60)
    try:
        output = wait_output(manager, job, '"status": "prepared"')
        request = GitApprovalRequest.from_payload(json.loads(output['stdout'].splitlines()[0])['request'])
        tools = create_git_tools(service.registry, service.sandbox, approved_pulls=service, job_manager=manager)
        result = tools.git_pull('repo', branch='refs/heads/reviewed', job_id=job,
            request_sha256=request.digest, approval_receipt=issue_git_approval(key, request))
        assert result['status'] == 'completed', result
        status = terminal(manager, job)
        assert status['status'] == 'cleanup_failed', status
        assert 'CONTINUED_COMMIT' in manager.get_output(job)['stdout']
        assert git(root, 'rev-parse', 'HEAD') == original
        assert not (root/'after-pull').exists()
    finally:
        if job in manager.active_processes:
            manager.cancel(job)
