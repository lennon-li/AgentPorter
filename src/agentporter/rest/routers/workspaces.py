from fastapi import APIRouter, Depends, Request
from typing import List, Dict, Any
from agentporter.rest.schemas import WorkspaceInfoResponse, WorkspaceDetailsResponse

router = APIRouter(prefix="/workspaces", tags=["Workspaces"])

@router.get("/", response_model=List[WorkspaceInfoResponse])
def list_workspaces(request: Request):
    """List all configured workspaces with ID and status."""
    return request.app.state.tools["list_workspaces"]()

@router.get("/{workspace_id}", response_model=WorkspaceDetailsResponse)
def workspace_info(workspace_id: str, request: Request):
    """Return comprehensive development context for a workspace."""
    return request.app.state.tools["workspace_info"](workspace_id)
