"""Fault-focused tests for generation 16 rollback availability and guard order."""
import importlib.util
from pathlib import Path
from types import SimpleNamespace

import pytest

REPO = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    'bcc_astra_rollout', REPO / 'scripts/bcc-astra-fixes-rollout.py'
)
ROLLOUT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ROLLOUT)


class FakeHelper:
    def __init__(self, events):
        self.events = events

    def profile_snapshot(self):
        self.events.append(('profile_snapshot',))


class FakeLibrary:
    AUTH_UNIT = SimpleNamespace(name='agentporter-auth.service')

    def __init__(self, events, *, fail_start=False):
        self.events = events
        self.fail_start = fail_start

    def restore(self, helper, state, *, release):
        self.events.append(('restore', release, tuple(state['files'])))

    def system(self, *args):
        self.events.append(('system', *args))
        if args[0] == 'start' and self.fail_start:
            raise RuntimeError('injected service start failure')
        if args[0] == 'is-active':
            return 'active'
        return ''

    def live(self, helper, role, release, fingerprint):
        self.events.append(('live', role, str(release), fingerprint))
        return 7000 + len(self.events)

    def release_guards(self, helper, state):
        self.events.append(('release_guards',))

    def save(self, state, phase):
        state['phase'] = phase
        self.events.append(('save', phase))


def state_with_empty_file_journal():
    return {
        'service_stop_intent': True,
        'files': {},
        'guarded': ['gateway', 'worker'],
        'baseline': {
            'releases': {
                role: {'fingerprint': 'baseline-' + role}
                for role in ROLLOUT.OLD
            },
        },
    }


def test_stop_intent_recovers_services_before_first_config_edit_and_guard_release():
    events = []
    lib = FakeLibrary(events)
    helper = FakeHelper(events)
    state = state_with_empty_file_journal()

    ROLLOUT.recover_after_failure(lib, helper, state)

    stop_index = events.index(('system', 'stop', ROLLOUT.QMAN.name))
    restore_index = events.index(('restore', False, ()))
    assert stop_index < restore_index
    start_index = events.index(('system', 'start', lib.AUTH_UNIT.name, ROLLOUT.QMAN.name))
    auth_check_index = events.index(('system', 'is-active', lib.AUTH_UNIT.name))
    qman_check_index = events.index(('system', 'is-active', ROLLOUT.QMAN.name))
    profile_index = events.index(('profile_snapshot',))
    release_index = events.index(('release_guards',))
    save_index = events.index(('save', 'cutover_rolled_back'))
    assert start_index < auth_check_index < qman_check_index < profile_index < release_index < save_index
    assert {event[1] for event in events if event[0] == 'live'} == set(ROLLOUT.OLD)
    assert state['service_stop_intent'] is False


def test_failure_before_stop_intent_releases_partial_guards_without_restore():
    events = []
    lib = FakeLibrary(events)
    helper = FakeHelper(events)
    state = state_with_empty_file_journal()
    state['service_stop_intent'] = False

    ROLLOUT.recover_after_failure(lib, helper, state)

    assert ('restore', False, ()) not in events
    assert events.index(('release_guards',)) < events.index(('save', 'cutover_failed_before_service_stop'))


def test_failed_baseline_restart_retains_guards():
    events = []
    lib = FakeLibrary(events, fail_start=True)
    helper = FakeHelper(events)
    state = state_with_empty_file_journal()

    with pytest.raises(RuntimeError, match='injected service start failure'):
        ROLLOUT.recover_after_failure(lib, helper, state)

    assert ('restore', False, ()) in events
    assert ('release_guards',) not in events
    assert events[-1] == ('save', 'cutover_recovery_failed_guards_retained')
