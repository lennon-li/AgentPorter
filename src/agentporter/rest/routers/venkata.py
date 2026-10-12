from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field
from agentporter.tools.venkata import Diagnostic
from agentporter.tools.venkata_transfer import TransferSource, TransferDestination

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


class VenkataTransferRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    source: TransferSource
    files: list[str] = Field(min_length=1, max_length=3)
    destination: TransferDestination = "laya-training"


@router.post("/transfer")
def venkata_transfer(workspace_id: str, req: VenkataTransferRequest, request: Request) -> dict:
    """Transfer approved files into a new checksummed batch on Venkata; never overwrite."""
    try:
        return request.app.state.tools["venkata_transfer"](
            workspace_id=workspace_id, source=req.source, files=req.files, destination=req.destination)
    except KeyError as exc:
        raise HTTPException(404, "Unknown workspace") from exc
    except PermissionError as exc:
        raise HTTPException(403, str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
