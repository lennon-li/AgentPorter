from fastapi import APIRouter, Request
from typing import List, Dict, Any, Optional
from agentporter.rest.schemas import (
    ListFilesRequest, SearchTextRequest, ReadFileRequest, WriteFileRequest,
    PatchFileRequest, MkdirRequest, MovePathRequest, TrashPathRequest,
    FileResponse, SearchResult, GenericActionResponse
)

router = APIRouter(prefix="/workspaces/{workspace_id}/files", tags=["Files"])

@router.post("/list", response_model=List[str])
def list_files(workspace_id: str, req: ListFilesRequest, request: Request):
    return request.app.state.tools["list_files"](workspace_id=workspace_id, path=req.path, depth=req.depth)

@router.post("/search", response_model=List[SearchResult])
def search_text(workspace_id: str, req: SearchTextRequest, request: Request):
    return request.app.state.tools["search_text"](workspace_id=workspace_id, query=req.query, glob=req.glob, max_results=req.max_results)

@router.post("/read", response_model=FileResponse)
def read_file(workspace_id: str, req: ReadFileRequest, request: Request):
    return request.app.state.tools["read_file"](workspace_id=workspace_id, path=req.path, start_line=req.start_line, end_line=req.end_line)

@router.post("/write", response_model=FileResponse)
def write_file(workspace_id: str, req: WriteFileRequest, request: Request):
    return request.app.state.tools["write_file"](workspace_id=workspace_id, path=req.path, content=req.content, expected_sha256=req.expected_sha256)

@router.post("/patch", response_model=GenericActionResponse)
def apply_patch(workspace_id: str, req: PatchFileRequest, request: Request):
    return request.app.state.tools["apply_patch"](workspace_id=workspace_id, patch=req.patch)

@router.post("/mkdir", response_model=GenericActionResponse)
def mkdir(workspace_id: str, req: MkdirRequest, request: Request):
    return request.app.state.tools["mkdir"](workspace_id=workspace_id, path=req.path)

@router.post("/move", response_model=GenericActionResponse)
def move_path(workspace_id: str, req: MovePathRequest, request: Request):
    return request.app.state.tools["move_path"](workspace_id=workspace_id, source=req.source, destination=req.destination)

@router.post("/trash", response_model=GenericActionResponse)
def trash_path(workspace_id: str, req: TrashPathRequest, request: Request):
    return request.app.state.tools["trash_path"](workspace_id=workspace_id, path=req.path)
