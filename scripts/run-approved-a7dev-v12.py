#!/usr/bin/python3
"""Verify and run the frozen A7Dev v12 activation launcher."""
import hashlib
from pathlib import Path

launcher = Path(__file__).resolve().with_name("install-approved-a7dev-v12.py")
source = launcher.read_bytes()
if hashlib.sha256(source).hexdigest() != "9c830da5083a6648285bafa4a84e4fc291d65bac72a9cd0da21185eb18fb82e8":
    raise SystemExit("Launcher changed: stop")
exec(compile(source, str(launcher), "exec"))
