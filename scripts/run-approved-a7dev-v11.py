#!/usr/bin/python3
"""Verify and run the frozen A7Dev v11 activation launcher."""
import hashlib
from pathlib import Path

launcher = Path(__file__).resolve().with_name("install-approved-a7dev-v11.py")
source = launcher.read_bytes()
if hashlib.sha256(source).hexdigest() != "4400068bc6c3be0f59c0485792515ff77d811d339fb78c0e7bfb4c615e468484":
    raise SystemExit("Launcher changed: stop")
exec(compile(source, str(launcher), "exec"))
