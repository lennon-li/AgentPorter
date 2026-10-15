"""REST Action endpoint for the fixed, read-only SciNet diagnostic."""

from typing import Literal

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field, model_validator

from agentporter.tools.scinet import ScinetDiagnostic
from agentporter.tools.scinet_training import ScinetExperiment, ScinetLogKind

router = APIRouter(prefix="/workspaces/{workspace_id}/scinet", tags=["SciNet"])


class ScinetDiagnosticRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    command: ScinetDiagnostic


class ScinetSubmitRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    stage_id: str = Field(min_length=32, max_length=32)
    experiment: ScinetExperiment = "laya_smoke"


ScinetSetupAction = Literal[
    "start", "status", "preflight", "environment_check", "record_approvals",
    "login_start", "login_status", "inference_preflight", "inference_stage",
    "inference_approve", "inference_submit", "inference_results",
]


class ScinetSetupRequest(BaseModel):
    """One consolidated Action so the API stays within the 30-operation Actions limit."""

    model_config = ConfigDict(extra="forbid")
    action: ScinetSetupAction
    stage_id: str | None = Field(default=None, min_length=32, max_length=32, pattern=r"^[a-f0-9]{32}$")
    job_id: str | None = Field(default=None, min_length=1, max_length=20, pattern=r"^[0-9]+$")
    experiment: ScinetExperiment = "laya_smoke"
    # Reviewer/confirmation also carry the exact stage-scoped inference approval.
    reviewer: str | None = Field(default=None, max_length=64)
    confirmation: str | None = Field(default=None, max_length=2048)
    approved_fields: list[str] | None = Field(default=None, max_length=5)
    device: Literal["cuda"] | None = None

    @model_validator(mode="after")
    def _approval_fields_only_for_record(self):
        extras = (self.reviewer, self.confirmation, self.approved_fields, self.device)
        if self.action != "inference_results" and self.job_id is not None:
            raise ValueError("job_id is only valid for inference_results")
        if self.action.startswith("inference_") and self.experiment != "laya_smoke":
            raise ValueError("inference actions use the separate laya_inference experiment")
        if self.action == "inference_preflight" and (
            self.stage_id is not None or self.experiment != "laya_smoke"
            or any(v is not None for v in extras)
        ):
            raise ValueError("inference_preflight does not accept a stage or training experiment")
        if self.action == "inference_stage" and (
            self.stage_id is not None or any(v is not None for v in extras)
        ):
            raise ValueError("inference_stage accepts no stage or approval fields")
        if self.action == "inference_approve":
            if self.stage_id is None or self.reviewer is None or self.confirmation is None:
                raise ValueError("inference_approve requires stage_id, reviewer, and confirmation")
            if self.approved_fields is not None or self.device is not None:
                raise ValueError("inference_approve does not accept training approval fields")
        if self.action == "inference_submit" and (
            self.stage_id is None or any(v is not None for v in extras)
        ):
            raise ValueError("inference_submit requires only stage_id")
        if self.action == "inference_results" and (
            self.job_id is None or self.stage_id is not None or any(v is not None for v in extras)
        ):
            raise ValueError("inference_results requires only numeric job_id")
        if self.action.startswith("inference_"):
            return self
        if self.confirmation is not None and len(self.confirmation) > 128:
            raise ValueError("training confirmation exceeds 128 characters")
        if self.action == "record_approvals":
            if None in extras[:3]:
                raise ValueError("reviewer, confirmation and approved_fields are required")
        elif any(v is not None for v in extras):
            raise ValueError("approval fields are only valid for record_approvals")
        return self


class ScinetJobRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    job_id: str = Field(min_length=1, max_length=32)


class ScinetJobLogsRequest(ScinetJobRequest):
    kind: ScinetLogKind = "all"


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


@router.post("/stage")
def scinet_stage(workspace_id: str, request: Request) -> dict:
    """Stage the fixed Laya handoff into the approved SciNet directory."""
    try:
        return request.app.state.tools["scinet_stage"](workspace_id=workspace_id)
    except KeyError as exc:
        raise HTTPException(404, "Unknown workspace") from exc
    except PermissionError as exc:
        raise HTTPException(403, str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc


@router.post("/submit")
def scinet_submit(workspace_id: str, req: ScinetSubmitRequest, request: Request) -> dict:
    """Submit one approval-gated, one-GPU Laya job from a fixed template (full runs need private opt-in)."""
    try:
        return request.app.state.tools["scinet_submit"](
            workspace_id=workspace_id, stage_id=req.stage_id, experiment=req.experiment
        )
    except KeyError as exc:
        raise HTTPException(404, "Unknown workspace or stage") from exc
    except PermissionError as exc:
        raise HTTPException(403, str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc


@router.post("/job-status")
def scinet_job_status(workspace_id: str, req: ScinetJobRequest, request: Request) -> dict:
    """Read status only for a job submitted through this workspace."""
    try:
        return request.app.state.tools["scinet_job_status"](
            workspace_id=workspace_id, job_id=req.job_id
        )
    except KeyError as exc:
        raise HTTPException(404, "Unknown workspace or job") from exc
    except PermissionError as exc:
        raise HTTPException(403, str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc


@router.post("/job-logs")
def scinet_job_logs(workspace_id: str, req: ScinetJobLogsRequest, request: Request) -> dict:
    """Retrieve bounded outputs and result metadata for an approved job."""
    try:
        return request.app.state.tools["scinet_job_logs"](
            workspace_id=workspace_id, job_id=req.job_id, kind=req.kind
        )
    except KeyError as exc:
        raise HTTPException(404, "Unknown workspace or job") from exc
    except PermissionError as exc:
        raise HTTPException(403, str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc


@router.post("/setup")
def scinet_setup(workspace_id: str, req: ScinetSetupRequest, request: Request) -> dict:
    """Manage SciNet setup, preflight, approvals, or login. ``login_start`` requests one Duo push; ``login_status`` checks the master. Tap approve on your phone; AgentPorter never accepts passcodes or approves Duo."""
    tools = request.app.state.tools
    try:
        if req.action in {"login_start", "login_status"}:
            return tools["scinet_login"](
                workspace_id=workspace_id,
                action="start" if req.action == "login_start" else "status",
            )
        if req.action == "environment_check":
            return tools["scinet_environment_check"](workspace_id=workspace_id)
        if req.action == "inference_preflight":
            return tools["scinet_inference_preflight"](workspace_id=workspace_id)
        if req.action == "inference_stage":
            return tools["scinet_inference_stage"](workspace_id=workspace_id)
        if req.action == "inference_approve":
            return tools["scinet_inference_approve"](
                workspace_id=workspace_id, stage_id=req.stage_id,
                reviewer=req.reviewer, confirmation=req.confirmation,
            )
        if req.action == "inference_submit":
            return tools["scinet_inference_submit"](
                workspace_id=workspace_id, stage_id=req.stage_id
            )
        if req.action == "inference_results":
            return tools["scinet_inference_results"](
                workspace_id=workspace_id, job_id=req.job_id
            )
        if req.stage_id is None:
            raise ValueError("stage_id is required for this action")
        if req.action == "record_approvals":
            return tools["scinet_record_approvals"](
                workspace_id=workspace_id, stage_id=req.stage_id, reviewer=req.reviewer,
                confirmation=req.confirmation, approved_fields=req.approved_fields,
                device=req.device or "cuda", experiment=req.experiment,
            )
        if req.action == "preflight":
            return tools["scinet_preflight"](
                workspace_id=workspace_id, stage_id=req.stage_id, experiment=req.experiment
            )
        name = "scinet_setup" if req.action == "start" else "scinet_setup_status"
        return tools[name](workspace_id=workspace_id, stage_id=req.stage_id)
    except KeyError as exc:
        raise HTTPException(404, "Unknown workspace or stage") from exc
    except PermissionError as exc:
        raise HTTPException(403, str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
