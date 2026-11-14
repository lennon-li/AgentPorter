"""Report the actual MCP registration and a shared dispatch ID constraint."""
from typing import Annotated, Optional
from pydantic import Field

DispatchRequestId = Annotated[Optional[str], Field(pattern=r'^[0-9a-f]{32}$')]


def add_catalog_diagnostics(result, mcp, policy):
    published = sorted(tool.name for tool in mcp._tool_manager.list_tools())
    result['supported_tools'] = published
    result['action_matrix'] = policy.snapshot()
    result['unpublished_actions'] = sorted(
        row['action'] for row in result['action_matrix'] if row['action'] not in published)
    result['published_mcp_count'] = len(published)

RepositorySelector = Annotated[Optional[str], Field(max_length=256)]
LocalBranchSelector = Annotated[Optional[str], Field(max_length=1024)]


def align_mcp_argument_schemas(mcp):
    """Use the REST FieldInfo for each shared argument, including all bounds.

    Workspace selectors remain MCP arguments / REST path parameters. Updating
    the SDK's argument model and its advertised schema keeps enforcement and
    discovery together, rather than merely editing schema text.
    """
    from copy import deepcopy
    from pydantic import create_model
    from agentporter.rest import schemas
    pairs = {'dispatch_agent':'DispatchAgentRequest', 'git_commit':'GitCommitRequest',
             'git_push':'GitPushRequest', 'git_fetch':'GitFetchRequest',
             'git_pull':'GitPullRequest', 'git_add':'GitAddRequest',
             'git_checkout':'GitCheckoutRequest', 'git_diff':'GitDiffRequest',
             'git_log':'GitLogRequest', 'git_show':'GitShowRequest',
             'git_branch':'GitBranchRequest'}
    for name, model_name in pairs.items():
        tool = mcp._tool_manager.get_tool(name)
        if tool is None:
            continue
        original = tool.fn_metadata.arg_model
        rest = getattr(schemas, model_name)
        fields = {key:(field.annotation, deepcopy(field))
                  for key,field in rest.model_fields.items()
                  if key in original.model_fields and key != 'workspace_id'}
        if set(fields) != set(original.model_fields) - {'workspace_id'}:
            raise RuntimeError('MCP/REST argument mapping needs explicit review: '+name)
        aligned = create_model(original.__name__+'RestContract', __base__=original, **fields)
        tool.fn_metadata.arg_model = aligned
        tool.parameters = aligned.model_json_schema(by_alias=True)
