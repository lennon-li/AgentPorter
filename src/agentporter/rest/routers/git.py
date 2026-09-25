from fastapi import APIRouter, Request
from typing import Dict, Any, Optional
from agentporter.rest.schemas import (
    GitDiffRequest, GitLogRequest, GitShowRequest
)

router = APIRouter(prefix="/workspaces/{workspace_id}/git", tags=["Git"])

@router.get("/status", response_model=str)
def git_status(workspace_id: str, request: Request):
    return request.app.state.tools["git_status"](workspace_id=workspace_id)

@router.post("/diff", response_model=str)
def git_diff(workspace_id: str, req: GitDiffRequest, request: Request):
    return request.app.state.tools["git_diff"](workspace_id=workspace_id, staged=req.staged)

@router.post("/log", response_model=str)
def git_log(workspace_id: str, req: GitLogRequest, request: Request):
    return request.app.state.tools["git_log"](workspace_id=workspace_id, limit=req.limit)

@router.post("/show", response_model=str)
def git_show(workspace_id: str, req: GitShowRequest, request: Request):
    return request.app.state.tools["git_show"](workspace_id=workspace_id, ref=req.ref)
