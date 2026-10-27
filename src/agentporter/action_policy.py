"""Fail-closed entrypoint for owner-specified public action restrictions.

This is phase-one policy enforcement, NOT a human-approval issuer or a confined
worker/publisher. A permissive override cannot disable a tool's own OS,
workspace, signature, or publication gates. Loaded once at server startup.
"""
from __future__ import annotations

import os
import stat
from pathlib import Path

import yaml

ALLOW_ACTIONS = frozenset({
    "get_capabilities",
    "server_deploy_info",
    "list_workspaces",
    "workspace_info",
    "list_agents",
    "qman_consult",
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
    "venkata_diagnostic",
    "scinet_diagnostic",
    "scinet_job_status",
    "scinet_job_logs",
    "scinet_setup_status",
    "scinet_inference_preflight",
    "scinet_inference_results",
    "scinet_preflight",
    "scinet_environment_check",
})

SCOPE_ACTIONS = frozenset({
    "write_file",
    "apply_patch",
    "mkdir",
    "move_path",
    "trash_path",
    "exec_run",
    "exec_start",
    "job_cancel",
    "git_add",
    "git_checkout",
    "dispatch_agent",
})

APPROVAL_ACTIONS = frozenset({
    "local_http_request",
    "venkata_transfer",
    "scinet_login",
    "scinet_stage",
    "scinet_submit",
    "scinet_setup",
    "scinet_inference_stage",
    "scinet_inference_provision",
    "scinet_inference_approve",
    "scinet_inference_submit",
    "git_fetch",
    "git_pull",
    "scinet_record_approvals",
})

LOCKED_ACTIONS = frozenset({
    "git_commit",
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

    def __init__(self, config_dir, workspace_roots=()):
        self.config_dir = Path(config_dir).resolve()
        for root in workspace_roots:
            root_path = Path(root).resolve()
            if self.config_dir == root_path or root_path in self.config_dir.parents:
                raise PermissionError("Operator policy directory cannot be agent workspace")
        self.overrides = self._load_overrides()

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
        if not isinstance(document, dict) or set(document) != {"version", "action_modes"}:
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
        return modes

    def effective_mode(self, action):
        if action not in DEFAULT_ACTION_MODES:
            raise PermissionError(f"Unknown public action: {action}")
        return self.overrides.get(action, DEFAULT_ACTION_MODES[action])

    def check(self, action, arguments):
        """Enforce owner-deny overrides now; never fake missing approval proof.

        Current specialized tool backends keep all existing restrictions. For
        modes which require a future verified approval/scope issuer, a newly
        stricter override fails closed. Default APPROVAL actions continue to
        use their existing specialized controls, not this unfinished issuer.
        """
        mode = self.effective_mode(action)
        baseline = DEFAULT_ACTION_MODES[action]
        if mode == "LOCKED" or baseline == "LOCKED":
            raise PermissionError(f"Action {action} is technically locked pending independently verified approval")
        if mode == "APPROVAL" and baseline in {"ALLOW", "SCOPE"}:
            raise PermissionError(f"Action {action} requires unavailable independent approval")
        if mode == "SCOPE" and baseline == "ALLOW" and not arguments.get("workspace_id"):
            raise PermissionError(f"Action {action} requires explicit workspace scope")
        return mode
