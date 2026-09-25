# Architectural & Implementation Plan: ChatGPT Web (Custom GPT Actions) Integration

## 1. Executive Summary

This document outlines the architecture and implementation roadmap for integrating AgentPorter with **ChatGPT Web (Plus/Team/Enterprise tiers)** via **Custom GPT Actions**. Since ChatGPT does not support client-side Model Context Protocol (MCP), AgentPorter must expose its tools via RESTful endpoints documented by an OpenAPI (Swagger) schema, while maintaining the existing Streamable HTTP (`/mcp`) endpoint for compatibility with Claude Desktop and Cursor.

## 2. Architecture & Dual-Protocol Gateway

Currently, AgentPorter uses `mcp.streamable_http_app` to return a raw Starlette `ASGIApp`, wrapped in a custom `SecurityMiddleware`. 

To support both MCP and REST natively, we will introduce **FastAPI** as the primary ASGI application. FastAPI is an extension of Starlette, which means it can easily mount the existing MCP app while adding strictly validated REST endpoints.

**Architecture Design:**
1. **Root Application**: A `FastAPI` instance configured with metadata tuned for ChatGPT's Action parser.
2. **REST Endpoints**: Grouped under `/api/v1/...`, bound directly to the existing internal tool functions (e.g., `_read_file`, `_exec_run`).
3. **MCP Sub-application**: The Starlette app returned by `mcp.streamable_http_app()` will be mounted at `/mcp`.
4. **Middleware**: The existing `SecurityMiddleware` (which validates `X-AgentPorter-Key`) will wrap the *outer* FastAPI application. This ensures a unified authentication layer regardless of the protocol accessed.

**FastAPI Initialization Pattern:**
```python
from fastapi import FastAPI
from mcp.server.transport_security import TransportSecuritySettings

def create_asgi_app(config: Config) -> ASGIApp:
    mcp_server, context = build_mcp_server(config)
    
    # 1. Create FastAPI Application
    app = FastAPI(
        title="AgentPorter Custom GPT Actions API",
        description="REST API for workspace operations, file manipulation, and agent execution.",
        version="0.1.0",
        servers=[{"url": config.server.public_url}] # Dynamically configured via CLI for OpenAPI accuracy
    )
    
    # 2. Mount MCP App
    mcp_app = mcp_server.streamable_http_app(
        transport_security=TransportSecuritySettings(enable_dns_rebinding_protection=False)
    )
    app.mount("/mcp", mcp_app)
    
    # 3. Include REST Routers
    from agentporter.rest.routers import files, workspace, exec, jobs, git, artifacts, agents
    app.include_router(files.router, prefix="/api/v1/files", tags=["Files"])
    app.include_router(workspace.router, prefix="/api/v1/workspace", tags=["Workspace"])
    # ... include other routers
    
    # 4. Wrap with existing Security Middleware
    return SecurityMiddleware(
        app=app,
        api_key=config.api_key,
        # ... other config
    )
```

## 3. REST Endpoints & Pydantic Schemas

To ensure ChatGPT reliably passes arguments, we will define explicit Pydantic `BaseModel` classes for every request and response. 

### Endpoint Mapping Strategy
| Domain | REST Route (POST/GET) | Underlying Tool Function |
| :--- | :--- | :--- |
| **Workspace** | `GET /api/v1/workspaces` | `list_workspaces` |
| | `GET /api/v1/workspaces/{workspace_id}` | `workspace_info` |
| **Files** | `POST /api/v1/files/list` | `list_files` |
| | `POST /api/v1/files/search` | `search_text` |
| | `POST /api/v1/files/read` | `read_file` |
| | `POST /api/v1/files/write` | `write_file` |
| | `POST /api/v1/files/patch` | `apply_patch` |
| **Exec** | `POST /api/v1/exec/run` | `exec_run` |
| | `POST /api/v1/exec/start` | `exec_start` |
| **Jobs** | `GET /api/v1/jobs/{job_id}/status` | `job_status` |
| | `GET /api/v1/jobs/{job_id}/output` | `job_output` |
| | `DELETE /api/v1/jobs/{job_id}` | `job_cancel` |
| **Git** | `GET /api/v1/git/{workspace_id}/status`| `git_status` |
| **Agents** | `POST /api/v1/agents/dispatch` | `dispatch_agent` |

*(Note: Similar mappings apply to all other existing tools like artifacts and other git commands).*

### Schema Design Example
Custom GPT Actions benefit immensely from verbose `description` fields on Pydantic models.

```python
from pydantic import BaseModel, Field
from typing import Optional, List

class WriteFileRequest(BaseModel):
    workspace_id: str = Field(..., description="The ID of the target workspace.")
    path: str = Field(..., description="Relative path to the file to write.")
    content: str = Field(..., description="The complete text content to write to the file.")
    expected_sha256: Optional[str] = Field(None, description="Optional SHA256 of the existing file to prevent race conditions.")

class WriteFileResponse(BaseModel):
    status: str = Field(..., description="Result of the operation, e.g., 'success'")
    path: str = Field(..., description="The path that was written to.")
    bytes_written: int = Field(..., description="Total bytes written.")
    sha256: str = Field(..., description="New SHA256 hash of the file.")
```

## 4. OpenAPI Schema Generation & Optimization for ChatGPT

ChatGPT's Action schema ingestor has specific quirks. We must optimize the automatically generated `/openapi.json` from FastAPI:

1. **Operation IDs**: FastAPI auto-generates long operation IDs (e.g., `read_file_api_v1_files_read_post`). We will override `generate_unique_id_function` or explicitly set `operation_id` on route decorators to short, descriptive names (e.g., `ReadFile`, `ExecRun`). ChatGPT uses these as function names.
2. **Flattened Payloads**: Avoid deeply nested JSON objects in request bodies where possible, as LLMs struggle to generate them correctly.
3. **Exposed OpenAPI Route**: Ensure `GET /openapi.json` bypasses the `SecurityMiddleware` (or requires no auth) so the ChatGPT configuration UI can easily import it. Wait, ChatGPT's UI requires the schema to be pasted or imported via URL. We can provide a CLI command to dump the schema: `agentporter schema --openapi`.
4. **Error Schemas**: Standardize error returns (e.g., HTTP 400 with a clear text detail message) so ChatGPT can self-correct when it provides invalid arguments.

## 5. Authentication, Ingress & Tunnel Compatibility

### Authentication
ChatGPT Custom Actions support two relevant authentication types:
1. **Custom Header**: (e.g., `X-AgentPorter-Key: <token>`)
2. **Bearer Token**: (e.g., `Authorization: Bearer <token>`)

AgentPorter's `SecurityMiddleware` currently supports checking custom headers. We will ensure it accepts `Authorization: Bearer <token>` as a fallback natively. This makes configuring the Action in ChatGPT's UI trivial (select "API Key" -> "Auth Type: Bearer").

### Microsoft Dev Tunnels (`devtunnel`)
To expose the local AgentPorter instance securely to ChatGPT Web, **Microsoft Dev Tunnels** will be supported as a premier option. It provides persistent subdomains and handles corporate firewall traversal.

**Setup Instructions for Users:**
1. Install Dev Tunnels CLI: `winget install Microsoft.devtunnel` (Windows) or via script for Linux/macOS.
2. Login: `devtunnel user login`
3. Create an anonymous tunnel (Required because ChatGPT needs to reach the tunnel, and we handle auth at the application layer):
   ```bash
   devtunnel create agentporter --allow-anonymous
   ```
4. Create the port binding:
   ```bash
   devtunnel port create agentporter -p 8765
   ```
5. Host the tunnel:
   ```bash
   devtunnel host agentporter
   ```
*The resulting URL (e.g., `https://random-id.usw2.devtunnels.ms`) is placed into the ChatGPT Action configuration as the Server URL.*

## 6. Testing & Acceptance Strategy

1. **Unit Testing REST Routes**: 
   - Introduce `fastapi.testclient.TestClient` tests in `tests/test_rest_gateway.py`.
   - Verify every tool endpoint properly maps Pydantic models to the underlying tool functions.
2. **Dual-Protocol Regression Test**:
   - Write tests ensuring that a single running instance serves `/mcp/` validly while simultaneously responding to `/api/v1/capabilities`.
3. **Schema Validation**:
   - Add a test that asserts the generated `openapi.json` contains no unresolved references and that all `operationId`s match a regex (e.g., `^[a-zA-Z0-9_]+$`) compatible with ChatGPT.
4. **Authentication Tests**:
   - Ensure REST endpoints reject requests lacking the Bearer token or `X-AgentPorter-Key`.

## 7. Step-by-Step Implementation Roadmap

**Phase 1: Dependencies & Core FastAPI Setup**
- [ ] Add `fastapi` to `pyproject.toml` dependencies.
- [ ] Refactor `src/agentporter/server.py` to instantiate `FastAPI`.
- [ ] Mount the MCP app to `/mcp`.
- [ ] Verify existing MCP clients (Cursor/Claude) still connect successfully.

**Phase 2: Schemas & Routers Definition**
- [ ] Create `src/agentporter/rest/schemas.py` and define Pydantic Request/Response models for all 26 tools.
- [ ] Create `src/agentporter/rest/routers/` with files grouping related endpoints (files, jobs, exec, workspace).
- [ ] Implement route handlers that invoke the underlying `_tool_functions`.

**Phase 3: Auth Expansion & OpenAPI Tuning**
- [ ] Update `SecurityMiddleware` to inspect `Authorization: Bearer <key>` headers.
- [ ] Configure FastAPI tags, server URLs, and concise `operation_id`s.
- [ ] Add `agentporter schema` CLI command to export the `openapi.json` to disk for easy copy-pasting into ChatGPT.

**Phase 4: Testing & Documentation**
- [ ] Implement `TestClient` suite for REST endpoints.
- [ ] Update `README.md` with instructions on setting up ChatGPT Custom Actions and Microsoft Dev Tunnels.
