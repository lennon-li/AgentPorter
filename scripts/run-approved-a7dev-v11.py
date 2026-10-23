#!/usr/bin/python3
"""Verify and run the frozen A7Dev v11 activation launcher."""
import hashlib
from pathlib import Path

launcher = Path(__file__).resolve().with_name("install-approved-a7dev-v11.py")
source = launcher.read_bytes()
if hashlib.sha256(source).hexdigest() != "610846cff654ebacf81d357c06ee25a0adbbcb38fc1f6f4485247a1df719751f":
    raise SystemExit("Launcher changed: stop")
exec(compile(source, str(launcher), "exec"))
