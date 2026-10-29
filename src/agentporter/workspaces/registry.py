"""Workspace registration, inspection, and lifecycle management."""

import os
import subprocess
import logging
from typing import Optional, Any
from agentporter.models import WorkspaceDefinition, WorkspaceInfo, GitContext

logger = logging.getLogger("agentporter.workspaces.registry")


class WorkspaceRegistry:
    """Registry managing registered workspaces and runtime inspection."""

    def __init__(self, workspaces: Optional[dict[str, dict[str, Any]]] = None, *, workspace_policy=None):
        self._workspaces: dict[str, WorkspaceDefinition] = {}
        self.workspace_policy = workspace_policy
        self.defaults = {"writable": True, "allow_execute": True, "allow_git": True, "allow_artifacts": True, "allow_agent_dispatch": False}
        if workspace_policy is not None:
            from agentporter.workspace_policy import CAPABILITIES
            self.defaults.update({field: value for cap, value in workspace_policy.defaults.items() if (field := CAPABILITIES[cap]) is not None})
            self.defaults["allow_agent_dispatch"] &= workspace_policy.delegation["enabled_by_default"]
        if workspaces:
            for ws_id, data in workspaces.items():
                self.register(
                    ws_id=ws_id,
                    path=data.get("path", ""),
                    writable=data.get("writable"),
                    description=data.get("description", ""),
                    allow_execute=data.get("allow_execute"),
                    allow_git=data.get("allow_git"),
                    allow_artifacts=data.get("allow_artifacts"),
                    allow_agent_dispatch=data.get("allow_agent_dispatch"),
                    local_http_ports=data.get("local_http_ports", []),
                    auto_discover=data.get("auto_discover", False),
                    allow_venkata_ssh=data.get("allow_venkata_ssh", False),
                    allow_venkata_transfer=data.get("allow_venkata_transfer", False),
            allow_scinet_diagnostic=data.get("allow_scinet_diagnostic", False),
                    allow_scinet_training=data.get("allow_scinet_training", False),
                )
            for ws_id, ws in list(self._workspaces.items()):
                if ws.auto_discover and os.path.isdir(ws.path):
                    try:
                        for entry in os.scandir(ws.path):
                            if entry.name.startswith(".") or entry.name in self._workspaces:
                                continue
                            if entry.is_dir(follow_symlinks=False):
                                self.register(
                                    ws_id=entry.name,
                                    path=entry.path,
                                    writable=ws.writable,
                                    description=f"Auto-discovered project in {ws.id}",
                                    allow_execute=ws.allow_execute,
                                    allow_git=ws.allow_git,
                                    allow_artifacts=ws.allow_artifacts,
                                    allow_agent_dispatch=ws.allow_agent_dispatch,
                                    auto_discover=False,
                                )
                    except OSError as exc:
                        logger.warning("Could not scan auto-discovery root %s: %s", ws.path, exc)

    def register(
        self,
        ws_id: str,
        path: str,
        writable: Optional[bool] = None,
        description: str = "",
        allow_execute: Optional[bool] = None,
        allow_git: Optional[bool] = None,
        allow_artifacts: Optional[bool] = None,
        allow_agent_dispatch: Optional[bool] = None,
        local_http_ports: Optional[list[int]] = None,
        auto_discover: bool = False,
        allow_venkata_ssh: bool = False,
        allow_venkata_transfer: bool = False,
        allow_scinet_diagnostic: bool = False,
        allow_scinet_training: bool = False,
    ) -> None:
        real_path = os.path.realpath(os.path.expanduser(path))
        ports = sorted({int(p) for p in (local_http_ports or []) if 1 <= int(p) <= 65535})
        self._workspaces[ws_id] = WorkspaceDefinition(
            id=ws_id,
            path=real_path,
            writable=self.defaults["writable"] if writable is None else writable,
            description=description,
            allow_execute=self.defaults["allow_execute"] if allow_execute is None else allow_execute,
            allow_git=self.defaults["allow_git"] if allow_git is None else allow_git,
            allow_artifacts=self.defaults["allow_artifacts"] if allow_artifacts is None else allow_artifacts,
            allow_agent_dispatch=self.defaults["allow_agent_dispatch"] if allow_agent_dispatch is None else allow_agent_dispatch,
            auto_discover=auto_discover,
            local_http_ports=ports,
            allow_venkata_ssh=allow_venkata_ssh,
            allow_venkata_transfer=allow_venkata_transfer,
            allow_scinet_diagnostic=allow_scinet_diagnostic,
            allow_scinet_training=allow_scinet_training,
        )

    def get(self, ws_id: str) -> WorkspaceDefinition:
        if ws_id not in self._workspaces:
            available = list(self._workspaces.keys())
            raise KeyError(f"Unknown workspace_id: '{ws_id}'. Available: {available}")
        return self._workspaces[ws_id]

    def list_all(self) -> list[dict]:
        results = []
        for ws_id, ws in self._workspaces.items():
            results.append({
                "workspace_id": ws.id,
                "path": ws.path,
                "exists": os.path.isdir(ws.path),
                "writable": ws.writable,
                "description": ws.description,
                "permissions": {
                    "execute": ws.allow_execute,
                    "git": ws.allow_git,
                    "artifacts": ws.allow_artifacts,
                    "agent_dispatch": ws.allow_agent_dispatch,
                    "local_http_ports": ws.local_http_ports,
                    "venkata_ssh": ws.allow_venkata_ssh,
                    "venkata_transfer": ws.allow_venkata_transfer,
                "scinet_diagnostic": ws.allow_scinet_diagnostic,
                    "scinet_training": ws.allow_scinet_training,
                },
            })
        return results

    def get_info(self, ws_id: str) -> dict:
        ws = self.get(ws_id)
        ws_path = ws.path

        if not os.path.isdir(ws_path):
            return {"error": f"Workspace directory does not exist on host: {ws_path}"}

        # Do not run Git on the host against a workspace controlled by a
        # collaborator. Even `git status` can execute repository configured
        # clean filters. Detailed Git inspection is available through the
        # confined Git tools; workspace_info reports unknown until it can use
        # that same boundary.
        git_branch = None
        git_dirty = None
        git_error = None
        git_dir = os.path.join(ws_path, ".git")
        if os.path.exists(git_dir):
            git_error = "Git inspection unavailable (use confined Git status)"

        # Language detection
        languages = []
        markers = []
        for fn in ["DESCRIPTION", "renv.lock", "NAMESPACE"]:
            if os.path.exists(os.path.join(ws_path, fn)):
                markers.append(fn)
                if "R" not in languages:
                    languages.append("R")

        for fn in ["pyproject.toml", "requirements.txt", "setup.py", "Pipfile"]:
            if os.path.exists(os.path.join(ws_path, fn)):
                markers.append(fn)
                if "Python" not in languages:
                    languages.append("Python")

        if not languages:
            for root, dirs, files in os.walk(ws_path):
                dirs[:] = [d for d in dirs if not d.startswith(".")]
                for f in files:
                    if f.endswith((".R", ".r", ".Rmd", ".qmd")):
                        if "R" not in languages:
                            languages.append("R")
                    elif f.endswith(".py"):
                        if "Python" not in languages:
                            languages.append("Python")
                if len(languages) >= 2:
                    break

        # Host runtime versions
        r_version = None
        try:
            r_ver = subprocess.run(["Rscript", "--version"], capture_output=True, text=True, timeout=5)
            r_version = (r_ver.stdout + r_ver.stderr).strip()
        except Exception:
            pass

        py_version = None
        try:
            py_ver = subprocess.run(["python3", "--version"], capture_output=True, text=True, timeout=5)
            py_version = py_ver.stdout.strip()
        except Exception:
            pass

        return {
            "workspace_id": ws.id,
            "path": ws.path,
            "exists": os.path.isdir(ws_path),
            "description": ws.description,
            "writable": ws.writable,
            "permissions": {
                "execute": ws.allow_execute,
                "git": ws.allow_git,
                "artifacts": ws.allow_artifacts,
                "agent_dispatch": ws.allow_agent_dispatch,
                "local_http_ports": ws.local_http_ports,
            },
            "git": {
                "is_repo": os.path.exists(git_dir),
                "branch": git_branch,
                "dirty": git_dirty,
                **({"error": git_error} if git_error else {}),
                **({"detached": git_branch is None} if git_dirty is not None else {}),
            },
            "languages": languages,
            "marker_files": markers,
            "r_version": r_version,
            "python_version": py_version,
        }
