#!/usr/bin/env python3
"""Prepare the action-map derivative of the pinned installed development release.

Unprivileged preparation only. No installation, credential reads, network or
policy changes. The runtime input is a private SHA-pinned expected baseline;
activation must independently match it using the trusted live runtime gate.
"""
import hashlib
import os
from pathlib import Path
import types

SOURCE = Path(__file__).with_name('prepare-a7dev-shared-access-repair.py')
SOURCE_SHA256 = 'ba4663accdc404a8ae5934bc7c1a5ce304a05b7e89683d7109a2c6394d3dd127'
INSTALLER_SHA256 = '48be445aa20af5d1be7428be9e9f7bdca8683a062fd6020dce73e8e45d96d620'
BASE_SHA256 = 'a5b30705a725369abfd5237f457cf179267af5272f4336967d73bdac82ae5d23'
BASE_VERSION = '20261022T224004.423620Z'
MODULES = {'src/agentporter/' + name for name in (
    'tools/files.py', 'tools/git.py', 'workspaces/registry.py', 'server.py',
    'rest/schemas.py', 'rest/routers/files.py')}
INERT = {
    "docs/agent7-asgard-actions.openapi.json": "operator-plan/agent7-asgard-actions.openapi.json",
    'tests/security/test_action_map_capabilities.py': 'operator-plan/validation/test_action_map_capabilities.py',
    'tests/security/test_file_response_contract.py': 'operator-plan/validation/test_file_response_contract.py',
    'tests/security/test_release_recovery_and_gate_privacy.py': 'operator-plan/validation/test_release_recovery_and_gate_privacy.py',
    'tests/security/test_development_artifact.py': 'operator-plan/validation/test_development_artifact.py',
    'tests/security/test_shared_workspace_access.py': 'operator-plan/validation/test_shared_workspace_access.py',
    'tests/security/test_scoped_git_metadata.py': 'operator-plan/validation/test_scoped_git_metadata.py',
    'scripts/install-development-artifact.py': 'operator-plan/install-development-artifact.py',
    'scripts/verify-a7dev-runtime-install-gate.py': 'operator-plan/verify-a7dev-runtime-install-gate.py',
}


def load_preparer():
    body = SOURCE.read_bytes()
    if hashlib.sha256(body).hexdigest() != SOURCE_SHA256:
        raise ValueError('Reviewed preparer changed')
    module = types.ModuleType('action_map_reviewed_preparer')
    module.__file__ = str(SOURCE)
    exec(compile(body, str(SOURCE), 'exec'), module.__dict__)
    frozen_root = os.environ.get('A7DEV_FROZEN_INPUT_ROOT')
    if frozen_root:
        module.ROOT = Path(frozen_root)
    original_load = module.load

    def load_with_reviewed_installer(name, expected):
        loaded = original_load(name, expected)
        if name == 'prepare-development-overlay':
            loaded.HELPERS = dict(loaded.HELPERS)
            loaded.HELPERS['install-development-artifact'] = INSTALLER_SHA256
        return loaded

    module.load = load_with_reviewed_installer
    module.BASE_SHA = BASE_SHA256
    module.OLD_VERSION = BASE_VERSION
    module.MODULES = set(MODULES)
    module.INERT = dict(INERT)

    def validate_release_delta(before, after, relocations):
        changed = sorted(name for name in set(before) | set(after) if before.get(name) != after.get(name))
        expected = MODULES | set(INERT.values()) | set(relocations)
        if not set(before) <= set(after) or set(changed) != expected:
            raise ValueError('Unexpected action-map release delta: ' + repr(changed))
        return changed

    module.validate_release_delta = validate_release_delta
    return module


if __name__ == '__main__':
    if os.geteuid() == 0:
        raise SystemExit('Never prepare a mutable candidate as root')
    load_preparer().main()
