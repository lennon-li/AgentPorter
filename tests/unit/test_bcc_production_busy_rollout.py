"""Fault-focused tests for generation 17 rollout entry and recovery."""
import importlib.util
from pathlib import Path
from types import SimpleNamespace

import pytest

REPO = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    'bcc_production_busy_rollout', REPO / 'scripts/bcc-production-busy-rollout.py'
)
ROLLOUT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ROLLOUT)


class FakeHelper:
    def __init__(self, events):
        self.events = events

    def profile_snapshot(self):
        self.events.append(('profile_snapshot',))


class SaveFailingLibrary:
    AUTH_UNIT = SimpleNamespace(name='agentporter-auth.service')

    def __init__(self, events):
        self.events = events
        self.failed_first_record = False

    def save(self, state, phase):
        self.events.append(('save', phase))
        if phase == 'cutover_failed' and not self.failed_first_record:
            self.failed_first_record = True
            raise OSError('injected failure-state write failure')
        state['phase'] = phase

    def system(self, *args):
        self.events.append(('system', *args))
        return 'active' if args[0] == 'is-active' else ''

    def restore(self, helper, state, *, release):
        self.events.append(('restore', release, tuple(state['files'])))

    def live(self, helper, role, release, fingerprint):
        self.events.append(('live', role, str(release), fingerprint))
        return f'baseline-pid-{role}'

    def release_guards(self, helper, state):
        self.events.append(('release_guards',))


def recovery_state():
    return {
        'phase': 'service_stop_intent',
        'service_stop_intent': True,
        'files': {'/etc/example.conf': {}},
        'guarded': ['gateway', 'worker'],
        'baseline': {
            'releases': {
                role: {'fingerprint': 'baseline-' + role}
                for role in ROLLOUT.OLD
            },
        },
    }


def test_failure_recording_error_still_restores_services_and_releases_guards():
    events = []
    lib = SaveFailingLibrary(events)
    helper = FakeHelper(events)
    state = recovery_state()

    with pytest.raises(OSError, match='injected failure-state write failure'):
        ROLLOUT._record_cutover_failure_and_recover(lib, helper, state)

    assert ('save', 'cutover_failed') in events
    assert ('restore', False, ('/etc/example.conf',)) in events
    assert ('system', 'start', lib.AUTH_UNIT.name, ROLLOUT.QMAN.name) in events
    assert ('system', 'is-active', lib.AUTH_UNIT.name) in events
    assert ('system', 'is-active', ROLLOUT.QMAN.name) in events
    assert ('profile_snapshot',) in events
    assert ('release_guards',) in events
    assert ('save', 'cutover_rolled_back') in events
    assert state['service_stop_intent'] is False


def test_optimized_python_is_rejected_before_protected_library_access(monkeypatch):
    monkeypatch.setattr(
        ROLLOUT.sys, 'flags',
        SimpleNamespace(optimize=1, isolated=True, dont_write_bytecode=True),
    )
    monkeypatch.setattr(ROLLOUT.os, 'getuid', lambda: 0)

    def forbidden_library_access(*args, **kwargs):
        raise AssertionError('optimized interpreter reached protected path access')

    monkeypatch.setattr(Path, 'lstat', forbidden_library_access)
    with pytest.raises(RuntimeError, match='refuses optimized Python'):
        ROLLOUT.main()
