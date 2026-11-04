"""Synthetic relay configuration shared by runtime security tests."""
import copy
from types import SimpleNamespace

from agentporter.agents.roster import PUBLIC_AGENT_IDS


def inputs():
    worker = {
        'config.yaml': {'sandbox': {'workspace_transactions': True}},
        'workspaces.yaml': {'workspaces': {}},
        'public-client-policy.yaml': {'version': 1, 'workspaces': {}},
        'development-runtime.yaml': {
            'enabled': True, 'profile': 'development', 'network_enabled': True,
            'egress_policy': 'provider_origin', 'public_client_policy_required': True,
            'job_resources': {'memory_bytes': 2147483648, 'pids': 128,
                              'cpu_quota_us': 200000, 'cpu_period_us': 100000},
            'allowed_workspace_roots': [],
        },
    }
    gateway = {
        'workspaces.yaml': {'workspaces': {}},
        'public-client-policy.yaml': {'version': 1, 'workspaces': {}},
    }
    return worker, gateway


def prepare(worker_documents, gateway_documents, *, agents):
    if not agents or len(set(agents)) != len(agents) or not set(agents) <= PUBLIC_AGENT_IDS:
        raise ValueError('Distinct configured worker profiles required')
    worker, gateway = copy.deepcopy((worker_documents, gateway_documents))
    workspace = {'path': plan.FIXTURE, 'writable': True,
                 'allow_execute': True, 'allow_agent_dispatch': True}
    scope = {'version': 1, 'workspaces': {plan.FIXTURE_ID: plan.FIXTURE}}
    for documents in (worker, gateway):
        documents['workspaces.yaml']['workspaces'][plan.FIXTURE_ID] = dict(workspace)
        documents['delegation-relay-write-scope.yaml'] = copy.deepcopy(scope)
    gateway['public-client-policy.yaml']['workspaces'][plan.FIXTURE_ID] = {
        'path': plan.FIXTURE, 'operations': ['read', 'write', 'dispatch', 'dispatch_write'],
    }
    runtime = worker['development-runtime.yaml']
    runtime['allowed_workspace_roots'].append({'path': plan.FIXTURE, 'writable': True})
    runtime['production_relay_agents'] = list(agents)
    worker['delegation-relay-scope.yaml'] = copy.deepcopy(scope)
    gateway['delegation-upstream.yaml'] = {
        'version': 1, 'host': '127.0.0.1', 'port': 8876, 'workspaces': [plan.FIXTURE_ID],
    }
    return worker, gateway


# The consuming fixtures replace FIXTURE with a pytest temporary directory.
plan = SimpleNamespace(FIXTURE_ID='relay-fixture', FIXTURE='/workspace/fixture', prepare=prepare)
