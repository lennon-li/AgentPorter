#!/usr/bin/env python3
"""Offline, read-only production source parity preflight.

Does not read secrets, mutate repositories, activate services or claim acceptance.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from pathlib import Path

SOURCE_PREFIX = "src/agentporter/"
CRITICAL = (
    "action_policy.py",
    "agents/roster.py",
    "sandbox/bubblewrap.py",
    "server.py",
    "tools/git.py",
    "tools/system.py",
)


def git(*args: str) -> str:
    return subprocess.check_output(["git", *args], text=True, stderr=subprocess.PIPE)


def files(rev: str) -> dict[str, str]:
    paths = [p for p in git("ls-tree", "-r", "--name-only", rev, SOURCE_PREFIX).splitlines() if p.endswith(".py")]
    return {p: hashlib.sha256(subprocess.check_output(["git", "show", f"{rev}:{p}"])).hexdigest() for p in paths}


def compare(left: str, right: str) -> dict:
    a, b = files(left), files(right)
    changed = sorted(p for p in a.keys() & b.keys() if a[p] != b[p])
    missing_left = sorted(b.keys() - a.keys())
    missing_right = sorted(a.keys() - b.keys())
    critical = sorted(p for p in changed + missing_left + missing_right if p.removeprefix(SOURCE_PREFIX) in CRITICAL)
    return {
        "left_commit": git("rev-parse", left).strip(),
        "right_commit": git("rev-parse", right).strip(),
        "common_ancestor": git("merge-base", left, right).strip(),
        "source_py_counts": {"left": len(a), "right": len(b)},
        "changed": changed,
        "left_only": missing_right,
        "right_only": missing_left,
        "critical_review_paths": critical,
        "source_identical": not (changed or missing_left or missing_right),
        "production_accepted": False,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--left", default="8dec760")
    parser.add_argument("--right", default="d7360e2")
    args = parser.parse_args()
    print(json.dumps(compare(args.left, args.right), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
