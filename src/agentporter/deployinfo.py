"""Code-version fingerprint for proving which AgentPorter source a process runs.

The service loads Python modules once at startup.  Editing ``src/`` (even with
an editable install) changes nothing until the process restarts, so "what is on
disk" and "what is serving requests" can silently diverge.  This module records
a SHA-256 fingerprint of the package source when it is first imported and can
recompute the on-disk fingerprint later, so operators and agents can see
``stale: true`` instead of guessing.
"""

from __future__ import annotations

import hashlib
import os
import sys
import time
from pathlib import Path
from typing import Any

from agentporter import __version__

PACKAGE_ROOT = Path(__file__).resolve().parent

# Modules whose resolved file paths prove where served code was imported from.
_PROOF_MODULES = (
    "agentporter",
    "agentporter.server",
    "agentporter.tools.scinet_training",
)


def source_fingerprint(root: Path | str = PACKAGE_ROOT) -> str:
    """Return a stable SHA-256 over every package file under ``root``.

    All files count (not only ``*.py``: templates and data change behaviour too)
    except ``__pycache__`` and ``*.pyc``.  Symlinks are hashed by their target
    text instead of being followed, so a link cannot smuggle in outside code
    unnoticed.  ``scripts/agentporter-deploy`` re-implements this exact
    algorithm in a standalone snippet; keep the two in sync (tested).
    """
    root = Path(root)
    entries = []
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        names = list(filenames) + [d for d in dirnames if os.path.islink(os.path.join(dirpath, d))]
        dirnames[:] = [d for d in dirnames if d != "__pycache__"]
        for name in names:
            full = Path(dirpath, name)
            rel = full.relative_to(root).as_posix()
            if name.endswith(".pyc"):
                continue
            if full.is_symlink():
                entries.append((rel, b"symlink:" + os.readlink(full).encode()))
            elif full.is_file():
                entries.append((rel, full.read_bytes()))
    digest = hashlib.sha256()
    for rel, payload in sorted(entries):
        digest.update(rel.encode())
        digest.update(b"\0")
        digest.update(payload)
        digest.update(b"\0")
    return digest.hexdigest()


_LOADED_FINGERPRINT = source_fingerprint()
_STARTED_AT = time.time()


def loaded_fingerprint() -> str:
    return _LOADED_FINGERPRINT


def deploy_info() -> dict[str, Any]:
    """Describe the running code and whether disk has moved on since import."""
    disk = source_fingerprint()
    modules = {}
    for name in _PROOF_MODULES:
        module = sys.modules.get(name)
        modules[name] = getattr(module, "__file__", None) if module else None
    return {
        "version": __version__,
        "pid": os.getpid(),
        "started_at": time.strftime("%Y-%m-%dT%H:%M:%S%z", time.localtime(_STARTED_AT)),
        "package_path": str(PACKAGE_ROOT),
        "python": sys.executable,
        "loaded_fingerprint": _LOADED_FINGERPRINT,
        "disk_fingerprint": disk,
        "stale": disk != _LOADED_FINGERPRINT,
        "modules": modules,
    }
