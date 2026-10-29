#!/usr/bin/python3
"""Verify and run the frozen A7Dev v10 activation launcher."""
import hashlib
from pathlib import Path

launcher = Path(__file__).resolve().with_name("install-approved-a7dev-v10.py")
source = launcher.read_bytes()
if hashlib.sha256(source).hexdigest() != "374a1c774f8be7a060e3064c0f9748ee11d3262c39e676bb4b1ca6c0ea77792d":
    raise SystemExit("Launcher changed: stop")
exec(compile(source, str(launcher), "exec"))
