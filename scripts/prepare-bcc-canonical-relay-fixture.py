#!/usr/bin/env python3
"""Pure staging-fixture configuration transform; never installs or restarts services."""
from __future__ import annotations

import copy

FIXTURE_ID = 'bcc-canonical-relay-fixture'
FIXTURE = '/home/yeli/repos/AgentPorter/artifacts/bcc-acceptance-current/owner-fixture'


def prepare(worker_documents, gateway_documents, *, agents):
    """Return independent configuration copies for one explicitly named fixture.

    The relay credential and protected mounts must be provisioned separately.
    This function does not read host configuration or apply its result.
    """
    if (not isinstance(agents, (list, tuple)) or not agents
            or any(not isinstance(a, str) or a not in {'jax', 'liz', 'prof', 'phil', 'ming', 'argie', 'wei'} for a in agents)
            or len(set(agents)) != len(agents)):
        raise ValueError('Explicit distinct named worker admissions required')
    worker = copy.deepcopy(worker_documents)
    gateway = copy.deepcopy(gateway_documents)
    wr = worker['workspaces.yaml']['workspaces']
    gr = gateway['workspaces.yaml']['workspaces']
    wp = worker['public-client-policy.yaml']['workspaces']
    gp = gateway['public-client-policy.yaml']['workspaces']
    runtime = worker['development-runtime.yaml']
    config = worker['config.yaml']
    bounds = {'memory_bytes': (512 * 1024**2, 16 * 1024**3), 'pids': (16, 512),
              'cpu_quota_us': (10000, 400000), 'cpu_period_us': (100000, 100000)}
    budgets = runtime.get('job_resources')
    if (runtime.get('enabled') is not True or runtime.get('profile') != 'development'
            or runtime.get('egress_policy') != 'provider_origin'
            or runtime.get('network_enabled') is not True
            or runtime.get('public_client_policy_required') is not True
            or not isinstance(budgets, dict) or set(budgets) != set(bounds)
            or any(type(budgets[k]) is not int or not low <= budgets[k] <= high
                   for k, (low, high) in bounds.items())
            or config.get('sandbox', {}).get('workspace_transactions') is not True):
        raise PermissionError('Expected supervised transactional isolated worker')
    if any(FIXTURE_ID in rows for rows in (wr, gr, wp, gp)):
        raise PermissionError('Fixture ID already registered')
    if any(row.get('path') == FIXTURE for row in [*wr.values(), *gr.values(), *runtime['allowed_workspace_roots']]):
        raise PermissionError('Canonical fixture already registered under another name')
    if any(key in docs for docs in (worker, gateway) for key in ('delegation-relay-scope.yaml', 'delegation-relay-write-scope.yaml')):
        raise PermissionError('Existing relay policy requires operator reconciliation')
    if any('delegation-upstream.yaml' in docs for docs in (worker, gateway)) or 'production_relay_agents' in runtime:
        raise PermissionError('Existing relay admissions require operator reconciliation')
    row = {'path': FIXTURE, 'writable': True, 'allow_execute': True, 'allow_agent_dispatch': True}
    wr[FIXTURE_ID] = copy.deepcopy(row)
    gr[FIXTURE_ID] = copy.deepcopy(row)
    gp[FIXTURE_ID] = {'path': FIXTURE, 'operations': ['read', 'write', 'dispatch', 'dispatch_write']}
    runtime['allowed_workspace_roots'].append({'path': FIXTURE, 'writable': True})
    runtime['production_relay_agents'] = list(agents)
    scope = {'version': 1, 'workspaces': {FIXTURE_ID: FIXTURE}}
    for docs in (worker, gateway):
        docs['delegation-relay-write-scope.yaml'] = copy.deepcopy(scope)
    worker['delegation-relay-scope.yaml'] = copy.deepcopy(scope)
    gateway['delegation-upstream.yaml'] = {'version': 1, 'host': '127.0.0.1', 'port': 8876,
                                            'workspaces': [FIXTURE_ID]}
    return worker, gateway
