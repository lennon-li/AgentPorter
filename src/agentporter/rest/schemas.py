from typing import Optional, List, Dict, Any, Union
from pydantic import BaseModel, Field, ConfigDict


# --- Responses ---

class WorkspaceInfoResponse(BaseModel):
    workspace_id: str = Field(description="The unique identifier of the workspace.")
    path: str = Field(description="Workspace absolute path")
    exists: bool = Field(description="Whether the workspace directory exists")
    writable: bool = Field(description="Whether the workspace is writable")
    description: str = Field(default="", description="Workspace description")

class WorkspaceDetailsResponse(BaseModel):
    workspace_id: str = Field(description="Workspace ID")
    path: str = Field(description="Workspace absolute path")
    exists: bool = Field(description="Whether the workspace exists")
    writable: bool = Field(description="Whether the workspace is writable")
    description: str = Field(default="")
    git_status: Optional[str] = Field(None, description="Git status output if applicable")
    language: Optional[str] = Field(None, description="Primary detected language")
    runtimes: Optional[List[str]] = Field(None, description="Available runtime environments")
    capabilities: Optional[List[str]] = Field(None)
    sandbox_status: Optional[str] = Field(None)

class FileResponse(BaseModel):
    path: str = Field(description="Path of the file.")
    content: Optional[str] = Field(None, description="Content of the file.")
    sha256: Optional[str] = Field(None, description="SHA256 checksum.")
    size_bytes: Optional[int] = Field(None, description="File size.")
    truncated: Optional[bool] = Field(None)

class SearchResult(BaseModel):
    file: str = Field(description="Path to the matching file.")
    line: int = Field(description="Line number.")
    text: str = Field(description="Matching text.")

class GenericActionResponse(BaseModel):
    success: Optional[bool] = Field(None, description="Whether the action was successful.")
    status: Optional[str] = Field(None, description="Status of the action.")
    message: Optional[str] = Field(None, description="Optional message.")
    path: Optional[str] = Field(None, description="Affected path.")
    trash_location: Optional[str] = Field(None)

class ExecResponse(BaseModel):
    stdout: str = Field(description="Standard output.")
    stderr: str = Field(description="Standard error.")
    exit_code: int = Field(description="Exit code.")
    timeout: bool = Field(default=False, description="True if timed out.")

class JobStartResponse(BaseModel):
    job_id: str = Field(description="Background job ID.")
    status: str = Field(description="Initial status.")

class JobStatusResponse(BaseModel):
    job_id: str = Field(description="Job ID.")
    status: str = Field(description="Current status (running, completed, failed, cancelled).")
    exit_code: Optional[int] = Field(None, description="Exit code if finished.")
    duration_seconds: Optional[float] = Field(None)

class JobOutputResponse(BaseModel):
    model_config = ConfigDict(extra="allow")

    job_id: str = Field(description="Job ID.")
    status: str = Field(description="Current status.")
    output: Optional[str] = Field(default="", description="Incremental or full output.")
    stdout: Optional[str] = Field(default="", description="Incremental stdout.")
    stderr: Optional[str] = Field(default="", description="Incremental stderr.")
    cursor: Optional[int] = Field(default=0, description="Start offset.")
    next_cursor: int = Field(default=0, description="Cursor for next read.")
    eof: Optional[bool] = Field(default=False, description="True if EOF reached.")
    exit_code: Optional[int] = Field(None, description="Exit code if finished.")


class JobResultResponse(BaseModel):
    job_id: str = Field(description="Job ID.")
    status: str = Field(description="Final status.")
    exit_code: Optional[int] = Field(None)
    stdout: str = Field(description="Full stdout.")
    stderr: str = Field(description="Full stderr.")

class ArtifactInfo(BaseModel):
    name: str = Field(description="Filename.")
    path: str = Field(description="Relative path.")
    size_bytes: int = Field(description="Size in bytes.")
    mtime: Optional[str] = Field(None, description="Modification time.")

class ArtifactContentResponse(BaseModel):
    path: str = Field(description="Relative artifact path.")
    type: str = Field(description="Artifact type: text or image.")
    mime_type: Optional[str] = Field(None, description="MIME type.")
    size_bytes: int = Field(description="Size in bytes.")
    content: Optional[str] = Field(None, description="Text content if text.")
    base64_data: Optional[str] = Field(None, description="Base64 encoded data if image.")
    truncated: Optional[bool] = Field(None, description="Whether content was truncated.")

class AgentInfo(BaseModel):
    agent: Optional[str] = Field(None, description="Agent identifier (e.g., codex, jax, liz, claude, opencode, copilot, agy).")
    name: Optional[str] = Field(None, description="Agent name.")
    worker_cli: Optional[str] = Field(None, description="Worker CLI binary name.")
    alias: Optional[str] = Field(None, description="Agent persona or alias.")
    provider: Optional[str] = Field(None, description="Model provider.")
    configured_model: Optional[str] = Field(None, description="Configured model name.")
    default_routing: Optional[str] = Field(None)
    actual_model_used: Optional[str] = Field(None)
    reasoning_level: Optional[str] = Field(None)
    cli_version: Optional[str] = Field(None)
    available: Optional[bool] = Field(None, description="Whether agent is available on host.")
    description: Optional[str] = Field(None, description="Agent description.")
    capabilities: Optional[List[str]] = Field(default_factory=list, description="Agent capabilities.")
    isolation_note: Optional[str] = Field(None)
    effective_model: Optional[str] = Field(None)
    default_model: Optional[str] = Field(None)

class DispatchResponse(BaseModel):
    model_config = ConfigDict(extra="allow")

    dispatch_id: Optional[str] = Field(default=None, description="Unique ID for the agent dispatch.")
    job_id: str = Field(description="Underlying background job ID.")
    status: str = Field(default="running", description="Status of dispatch.")
    worker_cli: Optional[str] = Field(None, description="Worker CLI binary name.")
    provider: Optional[str] = Field(None, description="Model provider.")
    selected_agent: Optional[str] = Field(None, description="Selected agent key.")
    alias: Optional[str] = Field(None, description="Agent persona or alias.")
    requested_model: Optional[str] = Field(None, description="Requested model.")
    actual_model: Optional[str] = Field(None, description="Actual model used.")
    model: Optional[str] = Field(None, description="Model name.")
    reasoning_level: Optional[str] = Field(None, description="Reasoning effort level.")
    thinking_level: Optional[str] = Field(None, description="Thinking level.")
    cli_version: Optional[str] = Field(None, description="CLI version.")
    workspace_id: Optional[str] = Field(None, description="Target workspace ID.")
    git_clean_at_dispatch: Optional[bool] = Field(None, description="Whether git tree was clean.")


# --- Requests ---

class ListFilesRequest(BaseModel):
    path: str = Field(default="", description="Relative path within the workspace to list files from.")
    depth: Optional[int] = Field(None, description="Maximum directory depth to traverse.")

class SearchTextRequest(BaseModel):
    query: str = Field(description="The regex or exact string to search for.")
    glob: str = Field(default="*", description="Glob pattern to filter files.")
    max_results: int = Field(default=50, description="Maximum number of matches to return.")

class ReadFileRequest(BaseModel):
    path: str = Field(description="Relative path of the file to read.")
    start_line: Optional[int] = Field(None, description="Start line (1-indexed).")
    end_line: Optional[int] = Field(None, description="End line (inclusive).")

class WriteFileRequest(BaseModel):
    path: str = Field(description="Relative path of the file to write.")
    content: str = Field(description="Full text content to write to the file.")
    expected_sha256: Optional[str] = Field(None, description="Optional SHA256 checksum for stale-file protection.")

class PatchFileRequest(BaseModel):
    patch: str = Field(description="Unified diff patch to apply to the workspace.")

class MkdirRequest(BaseModel):
    path: str = Field(description="Relative path of the directory to create.")

class MovePathRequest(BaseModel):
    source: str = Field(description="Source relative path.")
    destination: str = Field(description="Destination relative path.")

class TrashPathRequest(BaseModel):
    path: str = Field(description="Relative path to move to the .trash folder.")

class ExecRunRequest(BaseModel):
    argv: List[str] = Field(description="Command and arguments to execute.")
    cwd: str = Field(default="", description="Working directory for the command relative to workspace.")
    timeout_seconds: int = Field(default=30, description="Timeout in seconds for execution.")

class ExecStartRequest(BaseModel):
    argv: List[str] = Field(description="Command and arguments to execute.")
    cwd: str = Field(default="", description="Working directory for the command relative to workspace.")
    timeout_seconds: int = Field(default=300, description="Timeout in seconds for the background job.")

class JobOutputRequest(BaseModel):
    cursor: int = Field(default=0, description="Byte offset to start reading from.")
    max_bytes: int = Field(default=65536, description="Maximum bytes to return.")

class GitDiffRequest(BaseModel):
    staged: bool = Field(default=False, description="Whether to show staged changes (True) or unstaged (False).")

class GitLogRequest(BaseModel):
    limit: int = Field(default=10, description="Number of commits to show.")

class GitShowRequest(BaseModel):
    ref: str = Field(default="HEAD", description="Git object or commit ref to show.")

class ListArtifactsRequest(BaseModel):
    path: str = Field(default="artifacts", description="Relative path within workspace to look for artifacts.")

class DispatchAgentRequest(BaseModel):
    agent: str = Field(description="Name of the agent to dispatch.")
    task: str = Field(description="The specific task instruction for the agent.")
    purpose: str = Field(default="", description="Context or purpose for the dispatch.")
    model: Optional[str] = Field(None, description="Specific LLM model to use (if applicable).")
    reasoning_effort: Optional[str] = Field(None, description="Reasoning effort level (e.g., 'high', 'low').")

