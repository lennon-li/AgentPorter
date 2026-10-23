"""Fixed-purpose HTTPS metadata worker; never executes caller commands.

Invoked only by the broker's validated async-job entrypoint under an isolated
Python interpreter. Runs as host service identity but has a strictly bounded
and owner-scoped URL/method API; no secrets, shell, or proxy environment.
"""
from __future__ import annotations

import argparse
import sys

from agentporter.scoped_https import ScopedPublicHTTPS, ScopedPublicHTTPSPolicy


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(allow_abbrev=False)
    parser.add_argument("--config-dir", required=True)
    parser.add_argument("--workspace-id", required=True)
    parser.add_argument("--url", required=True)
    parser.add_argument("--method", required=True, choices=("GET", "HEAD"))
    parser.add_argument("--timeout", required=True, type=int)
    args = parser.parse_args(argv)
    try:
        # The service validates the workspace against its registry before
        # starting this trusted subprocess; the subprocess independently
        # reloads the operator-controlled exact-host policy.
        policy = ScopedPublicHTTPSPolicy(args.config_dir)
        broker = ScopedPublicHTTPS(policy)
        flags = "-fsS" if args.method == "GET" else "-sSI"
        result = broker.run(args.workspace_id, ["curl", flags, args.url], timeout_seconds=args.timeout)
        sys.stdout.write(result["stdout"])
        if result["stderr"]:
            sys.stderr.write(result["stderr"] + "\n")
        return int(result["exit_code"])
    except (PermissionError, ValueError, OSError) as exc:
        sys.stderr.write(f"Scoped public HTTPS denied: {type(exc).__name__}\n")
        return 77


if __name__ == "__main__":
    raise SystemExit(main())
