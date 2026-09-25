from fastapi import APIRouter, Request
from typing import List, Dict, Any
from agentporter.rest.schemas import DispatchAgentRequest, AgentInfo, DispatchResponse

router = APIRouter(prefix="/workspaces/{workspace_id}/agents", tags=["Agents"])

@router.get("/list", response_model=List[AgentInfo])
def list_agents(workspace_id: str, request: Request):
    return request.app.state.tools["list_agents"]()

@router.post("/dispatch", response_model=DispatchResponse)
def dispatch_agent(workspace_id: str, req: DispatchAgentRequest, request: Request):
    return request.app.state.tools["dispatch_agent"](
        agent=req.agent,
        task=req.task,
        workspace_id=workspace_id,
        purpose=req.purpose,
        model=req.model,
        reasoning_effort=req.reasoning_effort,
        allow_commit=req.allow_commit,
        allow_push=req.allow_push,
    )
