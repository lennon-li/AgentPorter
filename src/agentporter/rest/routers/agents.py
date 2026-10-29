from fastapi import APIRouter, HTTPException, Request
from typing import List, Dict, Any
from agentporter.rest.schemas import DispatchAgentRequest, AgentInfo, DispatchResponse

router = APIRouter(prefix="/workspaces/{workspace_id}/agents", tags=["Agents"])

@router.get("/list", response_model=List[AgentInfo])
def list_agents(workspace_id: str, request: Request):
    try:
        return request.app.state.tools["list_agents"](workspace_id=workspace_id)
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc

@router.post(
    "/dispatch",
    response_model=DispatchResponse,
    responses={403: {"description": "Delegation denied by server-side policy"}},
)
def dispatch_agent(workspace_id: str, req: DispatchAgentRequest, request: Request):
    try:
        return request.app.state.tools["dispatch_agent"](
            agent=req.agent,
            task=req.task,
            workspace_id=workspace_id,
            purpose=req.purpose,
            model=req.model,
            reasoning_effort=req.reasoning_effort,
            allow_commit=req.allow_commit,
            allow_push=req.allow_push,
            read_only=req.read_only,
            **({"approval_token": req.approval_token} if req.approval_token is not None else {}),
            **({"request_id": req.request_id} if req.request_id is not None else {}),
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=f"Dispatch prohibited: {exc}") from exc
