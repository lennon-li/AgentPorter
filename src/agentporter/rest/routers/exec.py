from fastapi import APIRouter, Request
from typing import Dict, Any
from agentporter.rest.schemas import (
    ExecRunRequest, ExecStartRequest, JobOutputRequest,
    ExecResponse, JobStartResponse, JobStatusResponse, JobOutputResponse, JobResultResponse, GenericActionResponse
)

router = APIRouter(prefix="/workspaces/{workspace_id}/exec", tags=["Exec"])
jobs_router = APIRouter(prefix="/jobs", tags=["Jobs"])

@router.post("/run", response_model=ExecResponse)
def exec_run(workspace_id: str, req: ExecRunRequest, request: Request):
    return request.app.state.tools["exec_run"](workspace_id=workspace_id, argv=req.argv, cwd=req.cwd, timeout_seconds=req.timeout_seconds)

@router.post("/start", response_model=JobStartResponse)
def exec_start(workspace_id: str, req: ExecStartRequest, request: Request):
    return request.app.state.tools["exec_start"](workspace_id=workspace_id, argv=req.argv, cwd=req.cwd, timeout_seconds=req.timeout_seconds)

@jobs_router.get("/{job_id}/status", response_model=JobStatusResponse)
def job_status(job_id: str, request: Request):
    return request.app.state.tools["job_status"](job_id=job_id)

@jobs_router.post("/{job_id}/output", response_model=JobOutputResponse)
def job_output(job_id: str, req: JobOutputRequest, request: Request):
    res = request.app.state.tools["job_output"](job_id=job_id, cursor=req.cursor, max_bytes=req.max_bytes)
    if "output" not in res or not res["output"]:
        res["output"] = res.get("stdout", "") or res.get("stderr", "")
    if "eof" not in res:
        res["eof"] = res.get("status") in ("completed", "failed", "cancelled")
    return res

@jobs_router.post("/{job_id}/result", response_model=JobResultResponse)
def job_result(job_id: str, req: JobOutputRequest, request: Request):
    return request.app.state.tools["job_result"](job_id=job_id, cursor=req.cursor, max_bytes=req.max_bytes)

@jobs_router.post("/{job_id}/cancel", response_model=GenericActionResponse)
def job_cancel(job_id: str, request: Request):
    return request.app.state.tools["job_cancel"](job_id=job_id)
