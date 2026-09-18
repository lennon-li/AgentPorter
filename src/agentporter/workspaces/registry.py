"""Workspace registration, inspection, and lifecycle management."""

import os
import subprocess
import logging
from typing import Optional, Any
from agentporter.models import WorkspaceDefinition, WorkspaceInfo, GitContext

logger = logging.getLogger("agentporter.workspaces.registry")


class WorkspaceRegistry:
    """Registry managing registered workspaces and runtime inspection."""

    def __init__(self, workspaces: Optional[dict[str, dict[str, Any]]] = None):
        self._workspaces: dict[str, WorkspaceDefinition] = {}
        if workspaces:
            for ws_id, data in workspaces.items():
                self.register(
                    ws_id=ws_id,
                    path=data.get("path", ""),
                    writable=data.get("writable", True),
                    description=data.get("description", ""),
                    allow_execute=data.get("allow_execute", True),
                    allow_git=data.get("allow_git", True),
                    allow_artifacts=data.get("allow_artifacts", True),
                    allow_agent_dispatch=data.get("allow_agent_dispatch", False),
                    local_http_ports=data.get("local_http_ports", []),
                )

    def register(
        self,
        ws_id: str,
        path: str,
        writable: bool = True,
        description: str = "",
        allow_execute: bool = True,
        allow_git: bool = True,
        allow_artifacts: bool = True,
        allow_agent_dispatch: bool = False,
        local_http_ports: Optional[list[int]] = None,
    ) -> None:
        real_path = os.path.realpath(os.path.expanduser(path))
        ports = sorted({int(p) for p in (local_http_ports or []) if 1 <= int(p) <= 65535})
        self._workspaces[ws_id] = WorkspaceDefinition(
            id=ws_id,
            path=real_path,
            writable=writable,
            description=description,
            allow_execute=allow_execute,
            allow_git=allow_git,
            allow_artifacts=allow_artifacts,
            allow_agent_dispatch=allow_agent_dispatch,
            local_http_ports=ports,
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
                },
            })
        return results

    def get_info(self, ws_id: str) -> dict:
        ws = self.get(ws_id)
        ws_path = ws.path

        if not os.path.isdir(ws_path):
            return {"error": f"Workspace directory does not exist on host: {ws_path}"}

        # Git details
        git_branch = None
        git_dirty = False
        git_dir = os.path.join(ws_path, ".git")
        if os.path.exists(git_dir):
            try:
                b_res = subprocess.run(["git", "branch", "--show-current"], cwd=ws_path, capture_output=True, text=True, timeout=5)
                git_branch = b_res.stdout.strip()
                s_res = subprocess.run(["git", "status", "--short"], cwd=ws_path, capture_output=True, text=True, timeout=5)
                git_dirty = bool(s_res.stdout.strip())
            except Exception:
                pass

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
            },
            "languages": languages,
            "marker_files": markers,
            "r_version": r_version,
            "python_version": py_version,
        }
