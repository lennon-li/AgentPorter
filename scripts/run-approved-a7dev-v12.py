#!/usr/bin/python3
"""Verify and run the frozen A7Dev v12 activation launcher."""
import hashlib
from pathlib import Path

launcher = Path(__file__).resolve().with_name("install-approved-a7dev-v12.py")
source = launcher.read_bytes()
if hashlib.sha256(source).hexdigest() != "d860325b2e0e033e060bc9aaad0ce64f5b6861f9353e6726f95c17ac17db6fe1":
    raise SystemExit("Launcher changed: stop")
exec(compile(source, str(launcher), "exec"))
