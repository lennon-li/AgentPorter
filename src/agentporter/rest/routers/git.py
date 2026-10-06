from fastapi import APIRouter, Request
from typing import Dict, Any, Optional
from agentporter.rest.schemas import (
    GitDiffRequest, GitLogRequest, GitShowRequest,
    GitFetchRequest, GitPullRequest, GitPushRequest,
    GitCommitRequest, GitAddRequest, GitBranchRequest,
    GitCheckoutRequest
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

@router.post("/fetch", response_model=str)
def git_fetch(workspace_id: str, req: GitFetchRequest, request: Request):
    return request.app.state.tools["git_fetch"](workspace_id=workspace_id, remote=req.remote)

@router.post("/pull", response_model=str)
def git_pull(workspace_id: str, req: GitPullRequest, request: Request):
    return request.app.state.tools["git_pull"](workspace_id=workspace_id, remote=req.remote, branch=req.branch)

@router.post("/push", response_model=str)
def git_push(workspace_id: str, req: GitPushRequest, request: Request):
    return request.app.state.tools["git_push"](
        workspace_id=workspace_id, remote=req.remote, branch=req.branch, set_upstream=req.set_upstream
    )

@router.post("/commit", response_model=str)
def git_commit(workspace_id: str, req: GitCommitRequest, request: Request):
    return request.app.state.tools["git_commit"](workspace_id=workspace_id, message=req.message, all_files=req.all_files)

@router.post("/add", response_model=str)
def git_add(workspace_id: str, req: GitAddRequest, request: Request):
    return request.app.state.tools["git_add"](workspace_id=workspace_id, paths=req.paths)

@router.get("/branch", response_model=str)
def git_branch(workspace_id: str, request: Request):
    return request.app.state.tools["git_branch"](workspace_id=workspace_id)

@router.post("/checkout", response_model=str)
def git_checkout(workspace_id: str, req: GitCheckoutRequest, request: Request):
    return request.app.state.tools["git_checkout"](workspace_id=workspace_id, branch=req.branch, create=req.create)
