#!/usr/bin/python3
"""Verify and run the frozen A7Dev v10 activation launcher."""
import hashlib
from pathlib import Path

launcher = Path(__file__).resolve().with_name("install-approved-a7dev-v10.py")
source = launcher.read_bytes()
if hashlib.sha256(source).hexdigest() != "3d1da37e64d89e172b597b570e40c80b2e905a44a778b93fdcdce904b8587d44":
    raise SystemExit("Launcher changed: stop")
exec(compile(source, str(launcher), "exec"))
