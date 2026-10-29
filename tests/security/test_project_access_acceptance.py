"""Classify the observed root ACL contract without connecting to MCP."""
import ast
import copy
from pathlib import Path

import pytest


@pytest.fixture
def validator():
    # Load just the constants and pure classifier: tests require neither MCP nor
    # service credentials and cannot accidentally start provider/network calls.
    path = Path(__file__).resolve().parents[2] / 'scripts/verify-a7dev-project-access.py'
    tree = ast.parse(path.read_text())
    selected = []
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(
                isinstance(t, ast.Name) and t.id in {'PROTECTED', 'TRAVERSE_ONLY'} for t in node.targets):
            selected.append(node)
        if isinstance(node, ast.FunctionDef) and node.name == 'summarize_workspace_access':
            selected.append(node)
    namespace = {}
    exec(compile(ast.Module(body=selected, type_ignores=[]), str(path), 'exec'), namespace)
    return namespace


@pytest.fixture
def observed(validator):
    roots = {name: {'read': name not in validator['TRAVERSE_ONLY'],
                    'protected': True, 'exec_denied': True}
             for name in validator['PROTECTED']}
    for name in validator['TRAVERSE_ONLY']:
        roots[name]['listing_denied_expected'] = True
    for number in range(41):
        roots[f'ordinary-{number}'] = {'read': True, 'protected': False,
            'offline_exec': True, 'read_write_remove': True, 'python': True, 'cwd': '/workspace'}
    return roots


def test_three_expected_listing_denials_pass_without_falsifying_read_flags(validator, observed):
    original = copy.deepcopy(observed)
    result = validator['summarize_workspace_access'](observed)
    assert result['failures'] == []
    assert result['ordinary_projects'] == 41
    assert result['ordinary_read_write_exec_passed'] == 41
    assert result['protected_traverse_only_listing_denied_expected'] == ['AgentPorter', 'agentporter', 'repos']
    assert result['protected_readable_roots_passed'] == ['asgard-hermes-review', 'obsidian']
    assert observed == original
    assert all(observed[n]['read'] is False for n in validator['TRAVERSE_ONLY'])


@pytest.mark.parametrize('flag', ['read', 'offline_exec', 'read_write_remove', 'python'])
def test_any_ordinary_read_execution_or_write_failure_rejected(validator, observed, flag):
    observed['ordinary-15'][flag] = False
    result = validator['summarize_workspace_access'](observed)
    assert result['failures'] == ['ordinary-15']
    assert result['ordinary_read_write_exec_passed'] == 40


def test_ordinary_wrong_cwd_rejected(validator, observed):
    observed['ordinary-0']['cwd'] = '/'
    assert validator['summarize_workspace_access'](observed)['failures'] == ['ordinary-0']


@pytest.mark.parametrize('name', ['obsidian', 'asgard-hermes-review'])
def test_other_protected_listing_failure_rejected(validator, observed, name):
    observed[name]['read'] = False
    assert validator['summarize_workspace_access'](observed)['failures'] == [name]


@pytest.mark.parametrize('name', ['agentporter', 'AgentPorter', 'repos'])
def test_traverse_only_listing_unexpectedly_allowed_rejected(validator, observed, name):
    observed[name]['read'] = True
    assert validator['summarize_workspace_access'](observed)['failures'] == [name]


@pytest.mark.parametrize('name', ['obsidian', 'asgard-hermes-review', 'agentporter', 'AgentPorter', 'repos'])
def test_every_protected_execution_denial_remains_required(validator, observed, name):
    observed[name]['exec_denied'] = False
    assert validator['summarize_workspace_access'](observed)['failures'] == [name]


def test_incomplete_inventory_rejected(validator, observed):
    del observed['ordinary-0']
    assert '__inventory__' in validator['summarize_workspace_access'](observed)['failures']


def test_missing_protected_root_rejected_even_if_total_count_unchanged(validator, observed):
    del observed['repos']
    observed['unexpected'] = copy.deepcopy(observed['ordinary-0'])
    assert '__inventory__' in validator['summarize_workspace_access'](observed)['failures']


def test_protection_classification_cannot_weaken_check(validator, observed):
    observed['ordinary-0']['protected'] = True
    observed['ordinary-0']['read_write_remove'] = False
    result = validator['summarize_workspace_access'](observed)
    assert result['failures'] == ['ordinary-0']
    assert 'protection classification mismatch' in result['failure_reasons']['ordinary-0']
