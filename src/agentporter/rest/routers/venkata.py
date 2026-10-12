from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field
from agentporter.tools.venkata import Diagnostic

router = APIRouter(prefix="/workspaces/{workspace_id}/venkata", tags=["Venkata"])


class VenkataDiagnosticRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    command: Diagnostic
    args: list[str] = Field(default_factory=list, max_length=3)


@router.post("/diagnostic")
def venkata_diagnostic(workspace_id: str, req: VenkataDiagnosticRequest, request: Request) -> dict:
    """Run an explicitly permitted read-only diagnostic on Venkata through BCC SSH."""
    try:
        return request.app.state.tools["venkata_diagnostic"](
            workspace_id=workspace_id, command=req.command, args=req.args)
    except KeyError as exc:
        raise HTTPException(404, "Unknown workspace") from exc
    except PermissionError as exc:
        raise HTTPException(403, str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
