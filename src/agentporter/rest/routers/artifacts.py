from fastapi import APIRouter, Request
from typing import List, Dict, Any
from agentporter.rest.schemas import ListArtifactsRequest, ArtifactInfo, ArtifactContentResponse

router = APIRouter(prefix="/workspaces/{workspace_id}/artifacts", tags=["Artifacts"])

@router.post("/list", response_model=List[ArtifactInfo])
def list_artifacts(workspace_id: str, req: ListArtifactsRequest, request: Request):
    return request.app.state.tools["list_artifacts"](workspace_id=workspace_id, path=req.path)

@router.get("/{path:path}", response_model=ArtifactContentResponse)
def read_artifact(workspace_id: str, path: str, request: Request):
    return request.app.state.tools["read_artifact"](workspace_id=workspace_id, path=path)
