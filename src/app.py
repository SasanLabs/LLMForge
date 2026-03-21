from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from .controllers.facade_compat_controller import router as facade_compat_router
from .controllers.meta_controller import router as meta_router
from .controllers.prompt_injection_controller import router as prompt_injection_router

app = FastAPI(title="LLMForge Prompt Injection Lab")
APP_BASE_PATH = "/llmforge"

static_dir = Path(__file__).resolve().parent / "static"
app.mount(f"{APP_BASE_PATH}/static", StaticFiles(directory=static_dir), name="static")


@app.get(APP_BASE_PATH, include_in_schema=False)
async def index_with_base_path() -> FileResponse:
	return FileResponse(static_dir / "index.html")


app.include_router(prompt_injection_router)
app.include_router(meta_router)
app.include_router(facade_compat_router)

# Base-path aliases so direct container access can use /llmforge/api/v1/...
app.include_router(prompt_injection_router, prefix=APP_BASE_PATH)
app.include_router(meta_router, prefix=APP_BASE_PATH)
app.include_router(facade_compat_router, prefix=APP_BASE_PATH)
