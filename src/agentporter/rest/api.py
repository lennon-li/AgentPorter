from fastapi import APIRouter
from fastapi.routing import APIRoute

from agentporter.rest.routers.workspaces import router as workspaces_router
from agentporter.rest.routers.files import router as files_router
from agentporter.rest.routers.exec import router as exec_router
from agentporter.rest.routers.exec import jobs_router
from agentporter.rest.routers.git import router as git_router
from agentporter.rest.routers.artifacts import router as artifacts_router
from agentporter.rest.routers.agents import router as agents_router

def custom_generate_unique_id(route: APIRoute) -> str:
    # Use the function name directly to have concise operation_ids like `list_workspaces`, `exec_run`
    return route.name

api_router = APIRouter()
api_router.include_router(workspaces_router)
api_router.include_router(files_router)
api_router.include_router(exec_router)
api_router.include_router(jobs_router)
api_router.include_router(git_router)
api_router.include_router(artifacts_router)
api_router.include_router(agents_router)
