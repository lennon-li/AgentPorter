"""Trust the mounted Git root across service UIDs without trusting other repos."""
import subprocess

import pytest
from tests._support import BWRAP_USABLE

from agentporter.sandbox.bubblewrap import BubblewrapSandbox
from agentporter.tools.git import create_git_tools
from agentporter.workspaces.registry import WorkspaceRegistry


@pytest.fixture
def repo(tmp_path):
    root = tmp_path / 'repo'
    root.mkdir()
    subprocess.run(['git', 'init', '-q'], cwd=root, check=True)
    (root / 'subdir').mkdir()
    (root / 'visible.txt').write_text('fixture\n')
    return root


def without_scoped_trust(args):
    result = []
    index = 0
    while index < len(args):
        if args[index] == '--setenv' and args[index + 1].startswith('GIT_CONFIG_'):
            index += 3
        else:
            result.append(args[index])
            index += 1
    return result


@pytest.mark.parametrize('cwd', ['', 'subdir'])
@pytest.mark.skipif(not BWRAP_USABLE, reason="Bubblewrap network namespaces unavailable on this host")
def test_native_git_owner_check_is_reproduced_and_fixed_only_for_mounted_root(tmp_path, repo, cwd):
    sandbox = BubblewrapSandbox(tmp_path / 'state')
    # This installed Git's own test switch exercises ownership rejection
    # without root/chown or touching an actual service user's repositories.
    command = ['env', 'GIT_TEST_ASSUME_DIFFERENT_OWNER=1', 'git', 'status', '--short']
    baseline = subprocess.run(
        without_scoped_trust(sandbox.build_bwrap_args(str(repo), writable=False, sub_cwd=cwd))
        + ['--', *command], capture_output=True, text=True, timeout=15)
    assert baseline.returncode == 128, baseline.stderr
    assert 'dubious ownership' in baseline.stderr
    result = sandbox.run(str(repo), command, cwd=cwd, writable=False)
    assert result['exit_code'] == 0, result
    assert 'visible.txt' in result['stdout']
    assert not (repo / '.git' / 'config.lock').exists()


@pytest.mark.skipif(not BWRAP_USABLE, reason="Bubblewrap network namespaces unavailable on this host")
def test_native_other_nested_repository_stays_untrusted(tmp_path, repo):
    child = repo / 'child'
    child.mkdir()
    subprocess.run(['git', 'init', '-q'], cwd=child, check=True)
    sandbox = BubblewrapSandbox(tmp_path / 'state')
    result = sandbox.run(str(repo), [
        'env', 'GIT_TEST_ASSUME_DIFFERENT_OWNER=1', 'git', '-C', '/workspace/child', 'status', '--short',
    ], writable=False)
    assert result['exit_code'] == 128, result
    assert 'dubious ownership' in result['stderr']
    assert '/workspace/child' in result['stderr']


def test_scoped_trust_has_no_wildcard_global_file_or_host_inheritance(tmp_path, repo, monkeypatch):
    monkeypatch.setenv('GIT_CONFIG_COUNT', '1')
    monkeypatch.setenv('GIT_CONFIG_KEY_0', 'safe.directory')
    monkeypatch.setenv('GIT_CONFIG_VALUE_0', '*')
    monkeypatch.setenv('GIT_CONFIG_GLOBAL', '/host/private/gitconfig')
    sandbox = BubblewrapSandbox(tmp_path / 'state')
    args = sandbox.build_bwrap_args(str(repo))
    environment = {args[i + 1]: args[i + 2] for i in range(len(args) - 2) if args[i] == '--setenv'}
    assert environment['GIT_CONFIG_COUNT'] == '1'
    assert environment['GIT_CONFIG_KEY_0'] == 'safe.directory'
    assert environment['GIT_CONFIG_VALUE_0'] == '/workspace'
    assert '/host/private/gitconfig' not in args
    assert '*' not in args
    assert '--clearenv' in args and '--unshare-net' in args
    assert ['--ro-bind', str(repo / '.git'), '/workspace/.git'] == args[
        args.index(str(repo / '.git')) - 1:args.index(str(repo / '.git')) + 2]


def test_dedicated_git_keeps_exact_root_trust_and_helper_restrictions(tmp_path, repo, monkeypatch):
    sandbox = BubblewrapSandbox(tmp_path / 'state')
    calls = []

    def capture(**kwargs):
        calls.append(kwargs)
        return {'exit_code': 0, 'stdout': '', 'stderr': ''}

    monkeypatch.setattr(sandbox, 'run', capture)
    registry = WorkspaceRegistry({'repo': {'path': str(repo), 'writable': True}})
    tools = create_git_tools(registry, sandbox)
    tools.git_status('repo')
    tools.git_diff('repo')
    tools.git_diff('repo', staged=True)
    tools.git_show('repo')
    for call in calls:
        argv = call['argv']
        assert argv[argv.index('safe.directory=/workspace') - 1] == '-c'
        assert 'safe.directory=*' not in argv
        assert 'core.fsmonitor=false' in argv
        assert 'core.hooksPath=/dev/null' in argv
        assert 'diff.external=' in argv
        assert call['network_access'] is False
        assert call['git_metadata_writable'] is False
    for call in calls[1:]:
        assert '--no-ext-diff' in call['argv']
        assert '--no-textconv' in call['argv']


@pytest.mark.skipif(not BWRAP_USABLE, reason="Bubblewrap network namespaces unavailable on this host")
def test_native_dedicated_git_works_under_assumed_owner_mismatch(tmp_path, repo, monkeypatch):
    sandbox = BubblewrapSandbox(tmp_path / 'state')
    original = sandbox.run

    def assumed_owner(**kwargs):
        kwargs['argv'] = ['env', 'GIT_TEST_ASSUME_DIFFERENT_OWNER=1', *kwargs['argv']]
        return original(**kwargs)

    monkeypatch.setattr(sandbox, 'run', assumed_owner)
    registry = WorkspaceRegistry({'repo': {'path': str(repo), 'writable': True}})
    tools = create_git_tools(registry, sandbox)
    result = tools.git_status('repo')
    assert 'Git error' not in result, result
    assert 'visible.txt' in result


@pytest.mark.skipif(not BWRAP_USABLE, reason="Bubblewrap network namespaces unavailable on this host")
def test_native_dedicated_diff_does_not_execute_repository_diff_helpers(tmp_path, repo):
    tracked = repo / 'tracked.txt'
    tracked.write_text('before\n')
    subprocess.run(['git', 'add', 'tracked.txt'], cwd=repo, check=True)
    tracked.write_text('after\n')
    (repo / '.gitattributes').write_text('tracked.txt diff=malicious\n')
    helper = repo / 'helper'
    helper.write_text('#!/bin/sh\necho FIXTURE_HELPER_EXECUTED\n')
    helper.chmod(0o755)
    for key in ('diff.malicious.command', 'diff.malicious.textconv'):
        subprocess.run(['git', 'config', key, '/workspace/helper'], cwd=repo, check=True)
    sandbox = BubblewrapSandbox(tmp_path / 'state')
    # Prove this fixture activates repository-local executable diff helpers.
    baseline = sandbox.run(str(repo), ['git', 'diff'], writable=False)
    assert baseline['exit_code'] == 0, baseline
    assert 'FIXTURE_HELPER_EXECUTED' in baseline['stdout'], baseline
    registry = WorkspaceRegistry({'repo': {'path': str(repo), 'writable': True}})
    result = create_git_tools(registry, sandbox).git_diff('repo')
    assert 'Git error' not in result, result
    assert 'FIXTURE_HELPER_EXECUTED' not in result
    assert '-before' in result and '+after' in result
    assert subprocess.check_output(['git', 'config', 'diff.malicious.command'], cwd=repo, text=True).strip() == '/workspace/helper'
