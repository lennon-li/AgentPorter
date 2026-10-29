#!/usr/bin/env python3
"""Prepare a Posit diagnostic only, preserving the installed CRAN baseline.

The archive runtime is an expected baseline, not a live capture. The pinned
runtime gate must prove it still matches immediately before installation.
No redirect is followed, owner policy changed, or service operated here.
"""
import hashlib
import os
from pathlib import Path
import types

SOURCE = Path(__file__).with_name('prepare-a7dev-cranary-source-repair.py')
SOURCE_SHA256 = '2115ab2f12bc43cb63b94ab53897d63c7d4a5886577959161067b74681452f8e'
BASE_SHA256 = 'a3af98891bb7d9660676656fe8a6c62388e3853710bba23dae965f51ea14a048'
BASE_VERSION = '20261022T204324.626687Z'
MODULES = {'src/agentporter/https_download.py'}


def load_preparer():
    body = SOURCE.read_bytes()
    if hashlib.sha256(body).hexdigest() != SOURCE_SHA256:
        raise ValueError('Reviewed CRAN preparer changed')
    wrapper = types.ModuleType('posit_reviewed_cran_preparer')
    wrapper.__file__ = str(SOURCE)
    exec(compile(body, str(SOURCE), 'exec'), wrapper.__dict__)
    module = wrapper.load_preparer()
    module.BASE_SHA = BASE_SHA256
    module.OLD_VERSION = BASE_VERSION
    module.MODULES = set(MODULES)
    module.INERT = {}
    return module


if __name__ == '__main__':
    if os.geteuid() == 0:
        raise SystemExit('Prepare only as the unprivileged owner')
    load_preparer().main()
