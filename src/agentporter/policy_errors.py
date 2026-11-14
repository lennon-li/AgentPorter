"""Public, bounded policy diagnostics shared by MCP and REST."""
import json
from mcp.server.mcpserver.exceptions import ToolError


class ActionPolicyDenied(PermissionError, ToolError):
    """Anticipated refusal, not an SDK-sanitized execution crash."""

    def __init__(self, action, mode, reason='action_locked'):
        self.detail = {'code': 'POLICY_DENIED', 'action': action,
                       'mode': mode, 'reason': reason}
        super().__init__(f'Action {action} is technically locked by protected policy; POLICY_DENIED: ' + json.dumps(self.detail, sort_keys=True))


class WorkspaceBusyError(PermissionError, ToolError):
    """A valid execution request could not acquire its workspace transaction."""

    def __init__(self):
        self.detail = {
            'status': 'busy', 'launched': False, 'executed': False,
            'error': {
                'code': 'WORKSPACE_BUSY',
                'reason': 'workspace_transaction_active',
                'message': 'Workspace already has an active transaction.',
                'retry_after_seconds': 3,
            },
        }
        super().__init__(json.dumps(self.detail, sort_keys=True))


def install_mcp_policy_results(mcp):
    """Represent an expected refusal as data, avoiding client argument-error mapping.

    The action still raises before repository lookup. Only its MCP presentation
    changes; REST and direct Python callers retain the PermissionError contract.
    """
    from functools import wraps
    from typing import Any, Dict, Literal, Union
    from pydantic import BaseModel, TypeAdapter
    class DenialDetail(BaseModel):
        code: Literal['POLICY_DENIED']
        action: Literal['git_commit','git_push']
        mode: Literal['LOCKED']
        reason: Literal['action_locked']
    class DenialResult(BaseModel):
        status: Literal['denied']
        executed: Literal[False]
        error: DenialDetail
    class BusyDetail(BaseModel):
        code: Literal['WORKSPACE_BUSY']
        reason: Literal['workspace_transaction_active']
        message: str
        retry_after_seconds: Literal[3]
    class BusyResult(BaseModel):
        status: Literal['busy']
        launched: Literal[False]
        executed: Literal[False]
        error: BusyDetail
    from mcp.types import CallToolResult, TextContent
    for name in ('git_commit', 'git_push', 'exec_run', 'exec_start'):
        tool = mcp._tool_manager.get_tool(name)
        if tool is None:
            continue
        # Keep success output validation and add the explicit refusal variant.
        # MCP output schemas remain object schemas; successful Git output keeps
        # its existing result wrapper. No authorization check is bypassed.
        prior = tool.fn_metadata.output_model
        if prior is not None:
            variants = [prior]
            if name in ('git_commit', 'git_push'):
                variants.append(DenialResult)
            if name in ('exec_run', 'exec_start'):
                variants.append(BusyResult)
            output = Union[tuple(variants)]
            tool.fn_metadata.output_model = output
            tool.fn_metadata.output_schema = dict(TypeAdapter(output).json_schema(), type='object')
        elif name in ('exec_run', 'exec_start'):
            # These tools have historically returned dictionaries with evolving
            # fields. Preserve arbitrary successful metadata while documenting
            # the bounded busy variant explicitly.
            output = Union[Dict[str, Any], BusyResult]
            tool.fn_metadata.output_model = output
            tool.fn_metadata.output_schema = dict(TypeAdapter(output).json_schema(), type='object')
        original = tool.fn
        def protect(fn):
            @wraps(fn)
            def wrapped(**kwargs):
                try:
                    return fn(**kwargs)
                except ActionPolicyDenied as exc:
                    value = {'status': 'denied', 'executed': False, 'error': exc.detail}
                    return CallToolResult(content=[TextContent(type='text', text=json.dumps(value))],
                                          structured_content=value, is_error=False)
                except WorkspaceBusyError as exc:
                    return CallToolResult(content=[TextContent(type='text', text=json.dumps(exc.detail))],
                                          structured_content=exc.detail, is_error=False)
            return wrapped
        tool.fn = protect(original)
