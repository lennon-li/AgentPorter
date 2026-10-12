"""REST Action endpoint for the fixed, read-only SciNet diagnostic."""

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, ConfigDict

from agentporter.tools.scinet import ScinetDiagnostic

router = APIRouter(prefix="/workspaces/{workspace_id}/scinet", tags=["SciNet"])


class ScinetDiagnosticRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    command: ScinetDiagnostic


@router.post("/diagnostic")
def scinet_diagnostic(
    workspace_id: str, req: ScinetDiagnosticRequest, request: Request
) -> dict:
    """Run one allowlisted SciNet diagnostic through Asgard's SSH master."""
    try:
        return request.app.state.tools["scinet_diagnostic"](
            workspace_id=workspace_id,
            command=req.command,
        )
    except KeyError as exc:
        raise HTTPException(404, "Unknown workspace") from exc
    except PermissionError as exc:
        raise HTTPException(403, str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
