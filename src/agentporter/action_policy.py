"""Fail-closed entrypoint for owner-specified public action restrictions.

This is phase-one policy enforcement, NOT a human-approval issuer or a confined
worker/publisher. A permissive override cannot disable a tool's own OS,
workspace, signature, or publication gates. Loaded once at server startup.
"""
from __future__ import annotations

import os
import hashlib
import re
from types import MappingProxyType
import stat
from pathlib import Path

import yaml

from agentporter.agents.roster import PUBLIC_AGENT_IDS
from agentporter.policy_errors import ActionPolicyDenied

ALLOW_ACTIONS = frozenset({
    "get_capabilities",
    "server_deploy_info",
    "list_workspaces",
    "workspace_info",
    "list_agents",
    "list_files",
    "search_text",
    "read_file",
    "list_artifacts",
    "read_artifact",
    "git_status",
    "git_diff",
    "git_log",
    "git_show",
    "git_branch",
    "job_status",
    "job_output",
    "job_result",
})

SCOPE_ACTIONS = frozenset({
    "write_file",
    "apply_patch",
    "mkdir",
    "move_path",
    "trash_path",
    "exec_run",
    "exec_start",
    "https_download",
    "job_cancel",
    "git_add",
    "git_checkout",
    "git_fetch",
    "git_pull",
    "dispatch_agent",
})

APPROVAL_ACTIONS = frozenset({
    "git_commit",
    "local_http_request",
})

LOCKED_ACTIONS = frozenset({
    "git_push",
})

DEFAULT_ACTION_MODES = {
    **{name: "ALLOW" for name in ALLOW_ACTIONS},
    **{name: "SCOPE" for name in SCOPE_ACTIONS},
    **{name: "APPROVAL" for name in APPROVAL_ACTIONS},
    **{name: "LOCKED" for name in LOCKED_ACTIONS},
}
VALID_MODES = frozenset(("ALLOW", "SCOPE", "APPROVAL", "LOCKED"))


class _UniqueKeysLoader(yaml.SafeLoader):
    """Reject duplicate policy keys rather than silently replacing one."""


def _unique_mapping(loader, node):
    result = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node)
        if not isinstance(key, str) or key in result:
            raise ValueError("Invalid or duplicate operator policy key")
        result[key] = loader.construct_object(value_node)
    return result


_UniqueKeysLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _unique_mapping
)


class OperatorActionPolicy:
    """Read operator-owned mode choices; never mint operator authority."""

    def __init__(self, config_dir, workspace_roots=(), *, approved_git_commits=False, approved_git_pushes=False):
        self.approved_git_commits = approved_git_commits is True
        self.approved_git_pushes = approved_git_pushes is True
        self.config_dir = Path(config_dir).resolve()
        for root in workspace_roots:
            root_path = Path(root).resolve()
            if self.config_dir == root_path or root_path in self.config_dir.parents:
                raise PermissionError("Operator policy directory cannot be agent workspace")
        self.scoped_modes = ()
        self._control_signature = None
        initial_identity = self._control_identity()
        self.overrides = MappingProxyType(self._load_overrides())
        self._control_signature = self._control_identity()
        if self._control_signature != initial_identity:
            raise PermissionError("Operator action policy changed while loading")

    def _load_overrides(self):
        path = self.config_dir / "action-policy.yaml"
        try:
            descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        except FileNotFoundError:
            return {}
        try:
            metadata = os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode):
                raise PermissionError("Operator action policy must be regular file")
            if metadata.st_uid not in {os.getuid(), 0} or metadata.st_mode & 0o077:
                raise PermissionError("Operator action policy must be owner-owned, mode 0600")
            if metadata.st_size > 65536:
                raise ValueError("Operator action policy exceeds 64 KiB limit")
            with os.fdopen(descriptor, "r", encoding="utf-8") as stream:
                descriptor = -1
                document = yaml.load(stream, Loader=_UniqueKeysLoader)
        finally:
            if descriptor >= 0:
                os.close(descriptor)
        if not isinstance(document, dict) or not {"version", "action_modes"} <= set(document) or set(document) - {"version", "action_modes", "scoped_modes"}:
            raise ValueError("action-policy.yaml requires version and action_modes")
        if type(document["version"]) is not int or document["version"] != 1:
            raise ValueError("Unsupported operator action policy version")
        modes = document["action_modes"]
        if not isinstance(modes, dict):
            raise ValueError("action_modes must be a mapping")
        for action, mode in modes.items():
            if action not in DEFAULT_ACTION_MODES:
                raise ValueError(f"Unknown public action policy ID: {action}")
            if type(mode) is not str or mode not in VALID_MODES:
                raise ValueError(f"Invalid policy mode for {action}")
        scoped = document.get("scoped_modes", [])
        if not isinstance(scoped, list):
            raise ValueError("scoped_modes must be a list")
        rows = []
        for row in scoped:
            if (not isinstance(row, dict) or not {"action", "mode"} <= set(row)
                    or set(row) - {"action", "mode", "workspace_id", "agent"}
                    or not ({"workspace_id", "agent"} & set(row))):
                raise ValueError("Invalid scoped action policy row")
            if (type(row["action"]) is not str or row["action"] not in DEFAULT_ACTION_MODES
                    or type(row["mode"]) is not str or row["mode"] not in VALID_MODES):
                raise ValueError("Unknown scoped action or mode")
            self._validate_selectors(row.get("workspace_id"), row.get("agent"))
            if any(row.get(key) is None for key in ("workspace_id", "agent") if key in row):
                raise ValueError("Empty scoped selector")
            rows.append(MappingProxyType(dict(row)))
        self.scoped_modes = tuple(rows)
        return dict(modes)

    @staticmethod
    def _validate_selectors(workspace_id, agent):
        if workspace_id is not None and (not isinstance(workspace_id, str) or
                re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", workspace_id) is None):
            raise ValueError("Invalid exact workspace selector")
        if agent is not None and (not isinstance(agent, str) or agent not in PUBLIC_AGENT_IDS):
            raise ValueError("Unknown named agent selector")

    def _control_identity(self):
        """Reject replacement/mutation rather than silently reloading authority."""
        directory = self.config_dir.stat()
        if directory.st_uid not in {0, os.getuid()} or directory.st_mode & 0o022:
            raise PermissionError("Operator policy directory is mutable by another principal")
        parent = (directory.st_dev, directory.st_ino, directory.st_uid, directory.st_gid,
                  stat.S_IMODE(directory.st_mode))
        try:
            fd = os.open(self.config_dir / "action-policy.yaml", os.O_RDONLY | os.O_NOFOLLOW)
        except FileNotFoundError:
            return parent, None
        try:
            st = os.fstat(fd)
            if (not stat.S_ISREG(st.st_mode) or st.st_uid not in {0, os.getuid()}
                    or st.st_mode & 0o077 or st.st_nlink != 1 or st.st_size > 65536):
                raise PermissionError("Operator action policy must be owner-owned, private, regular and singly linked")
            raw = os.read(fd, 65537)
            return parent, (st.st_dev, st.st_ino, st.st_uid, st.st_gid, st.st_mode, st.st_mtime_ns, st.st_ctime_ns,
                            hashlib.sha256(raw).hexdigest())
        finally:
            os.close(fd)

    def _assert_control(self):
        if self._control_identity() != self._control_signature:
            raise PermissionError("Operator action policy changed; restart with reviewed configuration")

    def effective_mode(self, action, *, workspace_id=None, agent=None):
        if action not in DEFAULT_ACTION_MODES:
            raise PermissionError(f"Unknown public action: {action}")
        self._assert_control()
        self._validate_selectors(workspace_id, agent)
        baseline = DEFAULT_ACTION_MODES[action]
        global_mode = self.overrides.get(action, baseline)
        matching = [row for row in self.scoped_modes if row["action"] == action and
                    all(row[key] == value for key, value in
                        (("workspace_id", workspace_id), ("agent", agent)) if key in row)]
        if baseline == "LOCKED" or global_mode == "LOCKED" or any(row["mode"] == "LOCKED" for row in matching):
            return "LOCKED"
        if not matching:
            return global_mode
        specificity = max(len(row) for row in matching)
        rank = {"ALLOW": 0, "SCOPE": 1, "APPROVAL": 2, "LOCKED": 3}
        return max((row["mode"] for row in matching if len(row) == specificity), key=rank.__getitem__)

    def snapshot(self, *, workspace_id=None, agent=None):
        """Pure effective catalog; does not enumerate scopes or promise backend access."""
        return [{"action": action, "mode": self.effective_mode(action, workspace_id=workspace_id, agent=agent),
                 "scope_condition": (self.effective_mode(action, workspace_id=workspace_id, agent=agent) == "SCOPE"
                                     or any(row["action"] == action for row in self.scoped_modes)),
                 "backend_checks_required": True}
                for action in sorted(DEFAULT_ACTION_MODES)]

    def check(self, action, arguments):
        """Enforce owner-deny overrides now; never fake missing approval proof.

        Current specialized tool backends keep all existing restrictions. For
        modes which require a future verified approval/scope issuer, a newly
        stricter override fails closed. Default APPROVAL actions continue to
        use their existing specialized controls, not this unfinished issuer.
        """
        try:
            mode = self.effective_mode(action, workspace_id=arguments.get("workspace_id"),
                                       agent=arguments.get("agent"))
        except ValueError as error:
            raise PermissionError("Unapproved named agent or workspace selector") from error
        baseline = DEFAULT_ACTION_MODES[action]
        if action == "dispatch_agent":
            read_only = arguments.get("read_only", True)
            if type(read_only) is not bool:
                raise PermissionError("Delegation read_only must be a boolean")
            if arguments.get('allow_commit') or arguments.get('allow_push'):
                raise PermissionError('Worker commit/push flags cannot grant independent owner approval')
        if mode == "LOCKED" or baseline == "LOCKED":
            raise ActionPolicyDenied(action, 'LOCKED')
        if mode == "APPROVAL" and baseline in {"ALLOW", "SCOPE"}:
            raise PermissionError(f"Action {action} requires unavailable independent approval")
        if mode == "SCOPE" and baseline == "ALLOW" and not arguments.get("workspace_id"):
            raise PermissionError(f"Action {action} requires explicit workspace scope")
        return mode
