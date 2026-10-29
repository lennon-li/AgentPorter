#!/usr/bin/env python3
"""Issue a scoped production token offline in the owner's root terminal."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys
import time
import uuid

from agentporter.scoped_approvals import (
    ApprovalError, canonical_arguments, load_private_key, read_private_file, sign_grant,
)
from agentporter.workspace_policy import load_workspace_policy

ISSUER_KEY = Path("/etc/agentporter/approval-issuer.key")


def _read_request(path: str) -> dict:
    raw = read_private_file(path, owner_uid=os.geteuid())

    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ApprovalError("Duplicate request JSON key")
            result[key] = value
        return result

    try:
        result = json.loads(raw, object_pairs_hook=unique)
        canonical_arguments(result)
        return result
    except (ValueError, TypeError, UnicodeError) as exc:
        raise ApprovalError("Invalid request JSON") from exc


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", required=True)
    parser.add_argument("--agent")
    parser.add_argument("--action", required=True, choices=["dispatch_agent", "exec_run", "exec_start", "git_commit", "git_push", "destructive"])
    parser.add_argument("--request-json", required=True)
    parser.add_argument("--operations", required=True, help="Explicit comma-separated write,delete,commit,push")
    parser.add_argument("--ttl", required=True, type=int)
    parser.add_argument("--approve", action="store_true", help="Explicitly approve and sign; otherwise print an unsigned plan")
    args = parser.parse_args(argv)
    if args.approve and os.geteuid() != 0:
        raise ApprovalError("Issuing production approval requires the owner's root terminal")
    if not 0 < args.ttl <= 3600:
        raise ApprovalError("TTL must be between 1 and 3600 seconds")
    policy = load_workspace_policy()
    if args.workspace not in policy.workspaces:
        raise ApprovalError("Workspace is not registered in the shared production policy")
    operations = args.operations.split(",")
    if not operations or len(operations) != len(set(operations)) or not set(operations) <= {"write", "delete", "commit", "push"}:
        raise ApprovalError("Operations must be an explicit bounded set")
    if not policy.capabilities(args.workspace)["writable"]:
        raise ApprovalError("Workspace is read-only in the shared production policy")
    if args.action == "dispatch_agent" and not args.agent:
        raise ApprovalError("Dispatch approval requires an exact agent")
    action_operation = {"git_commit": "commit", "git_push": "push", "destructive": "delete"}.get(args.action)
    if action_operation and action_operation not in operations:
        raise ApprovalError("Action requires its explicit operation")
    arguments = _read_request(args.request_json)
    from agentporter.task_authorization import normalize_task_arguments
    arguments = normalize_task_arguments(args.action, arguments, workspace_id=args.workspace, agent=args.agent if args.action == "dispatch_agent" else None)
    canonical_arguments(arguments)
    root = str(Path(policy.workspaces[args.workspace]["path"]).resolve())
    plan = dict(workspace_id=args.workspace, workspace_root=root, action=args.action,
                agent=args.agent, operations=operations, ttl=args.ttl)
    if not args.approve:
        print(json.dumps({**plan, "approval_required": True}, sort_keys=True))
        return 0
    now = int(time.time())
    token = sign_grant(load_private_key(ISSUER_KEY), workspace_id=args.workspace, workspace_root=root,
                       action=args.action, arguments=arguments, operations=operations,
                       expires_at=now + args.ttl, issued_at=now, agent=args.agent)
    print(json.dumps({**plan, "approval_token": token, "request_id": uuid.uuid4().hex}, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ApprovalError, PermissionError) as exc:
        print(str(exc), file=sys.stderr)
        raise SystemExit(1)
