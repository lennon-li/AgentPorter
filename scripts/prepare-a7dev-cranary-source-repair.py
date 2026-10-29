#!/usr/bin/env python3
"""Prepare a code-only A7Dev CRAN derivative; never install or apply policy.

Reuse the verified archive/snapshot workflow with a single admitted package
module. Owner-policy examples and validation inputs are inert release evidence.
The mandatory install gate still requires the exact live runtime snapshot.
"""
import hashlib
import os
from pathlib import Path
import types


SOURCE = Path(__file__).with_name('prepare-a7dev-shared-access-repair.py')
SOURCE_SHA256 = 'ba4663accdc404a8ae5934bc7c1a5ce304a05b7e89683d7109a2c6394d3dd127'
BASE_SHA256 = 'ce546675f17f6e6e70a39d196ac763b3bbe155de67ad39f24af057e95e22d5b9'
BASE_VERSION = '20261022T181133.685266Z'
MODULES = {'src/agentporter/scoped_https.py'}
INERT = {
    'scripts/enable-a7dev-all-cran-paths.py':
        'operator-plan/enable-a7dev-all-cran-paths.py',
    'tests/security/test_cran_policy_operator.py':
        'operator-plan/validation/test_cran_policy_operator.py',
    'scripts/verify-a7dev-cranary-acquisition.py':
        'operator-plan/verify-a7dev-cranary-acquisition.py',
    'scripts/verify-a7dev-cranary-https.py':
        'operator-plan/verify-a7dev-cranary-https.py',
    'tests/security/test_acquisition_acceptance_routing.py':
        'operator-plan/validation/test_acquisition_acceptance_routing.py',
    'docs/examples/a7dev-cranary-all-cran-paths-https.yaml':
        'operator-plan/a7dev-cranary-all-cran-paths-https.yaml',
    'docs/cranary-source-download-repair-20261022.md':
        'operator-plan/cranary-source-download-repair-20261022.md',
    'tests/security/test_cran_download_scope.py':
        'operator-plan/validation/test_cran_download_scope.py',
    'tests/security/test_https_acquisition.py':
        'operator-plan/validation/test_https_acquisition.py',
    'tests/security/test_acquisition_receipts.py':
        'operator-plan/validation/test_acquisition_receipts.py',
    'tests/unit/test_scoped_https.py':
        'operator-plan/validation/test_scoped_https.py',
}


def load_preparer(source=None):
    source = SOURCE if source is None else Path(source)
    body = source.read_bytes()
    if hashlib.sha256(body).hexdigest() != SOURCE_SHA256:
        raise ValueError('Candidate preparer SHA256 changed; review required')
    module = types.ModuleType('cranary_verified_preparer')
    module.__file__ = str(SOURCE)
    exec(compile(body, str(SOURCE), 'exec'), module.__dict__)
    module.BASE_SHA = BASE_SHA256
    module.OLD_VERSION = BASE_VERSION
    module.MODULES = set(MODULES)
    module.INERT = dict(INERT)

    def validate_release_delta(before, after, relocations):
        changed = sorted(name for name in set(before) | set(after)
                         if before.get(name) != after.get(name))
        admitted = module.MODULES | set(relocations) | set(module.INERT.values())
        required = module.MODULES | set(relocations)
        if (not set(before) <= set(after) or not set(changed) <= admitted
                or not required <= set(changed)):
            raise ValueError('Unexpected CRAN release payload delta: ' + repr(changed))
        return changed

    module.validate_release_delta = validate_release_delta
    return module


if __name__ == '__main__':
    if os.geteuid() == 0:
        raise SystemExit('Never execute mutable candidate preparation as root')
    load_preparer().main()
