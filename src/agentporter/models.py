"""Data models and schemas for AgentPorter."""

from typing import Optional, Any
from pydantic import BaseModel, Field


class WorkspaceDefinition(BaseModel):
    id: str
    path: str
    writable: bool = True
    description: str = ""


class GitContext(BaseModel):
    is_repo: bool = False
    branch: Optional[str] = None
    dirty: bool = False


class WorkspaceInfo(BaseModel):
    workspace_id: str
    path: str
    writable: bool
    git: GitContext
    languages: list[str] = Field(default_factory=list)
    marker_files: list[str] = Field(default_factory=list)
    r_version: Optional[str] = None
    python_version: Optional[str] = None


class JobStatus(BaseModel):
    job_id: str
    workspace_id: str
    worker_cli: str
    agent: str
    provider: str
    requested_model: str
    actual_model: str
    reasoning_level: str
    cli_version: str
    status: str
    exit_status: Optional[int] = None
    exit_code: Optional[int] = None
    created_at: float
    started_at: Optional[float] = None
    finished_at: Optional[float] = None
    duration: float = 0.0
    model: str


class AgentMetadata(BaseModel):
    agent: str
    worker_cli: str
    alias: str
    provider: str
    configured_model: str
    default_routing: str
    actual_model_used: str = "unknown (resolved at runtime per dispatch)"
    reasoning_level: str
    cli_version: str
    available: bool
    capabilities: list[str] = Field(default_factory=list)
    description: str
    isolation_note: str = "Runs with host user credentials; scoped by cwd and control block."
    effective_model: str
    default_model: str


class AgentDispatchResult(BaseModel):
    worker_cli: str
    provider: str
    requested_model: str
    actual_model: str = "unknown"
    reasoning_level: str
    cli_version: str
    job_id: str
    exit_status: Optional[int] = None
    duration: float = 0.0
    status: str = "running"
    selected_agent: str
    alias: str
    model: str
    thinking_level: str
    workspace_id: str
    git_clean_at_dispatch: bool
