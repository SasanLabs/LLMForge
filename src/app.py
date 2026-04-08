from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from .controllers.facade_compat_controller import router as facade_compat_router
from .controllers.meta_controller import router as meta_router
from .config import APP_BASE_PATH

# Framework-based controllers
from .controllers.prompt_injection_controller import PromptInjectionController
from .controllers.indirect_prompt_injection_controller import IndirectPromptInjectionController
from .framework import register_controllers

app = FastAPI(title="LLMForge Prompt Injection Lab")

static_dir = Path(__file__).resolve().parent / "static"
app.mount(f"{APP_BASE_PATH}/static", StaticFiles(directory=static_dir), name="static")


@app.get(APP_BASE_PATH, include_in_schema=False)
async def index_with_base_path() -> FileResponse:
	return FileResponse(static_dir / "index.html")


# Register framework-based controllers
register_controllers(app, route_prefix=APP_BASE_PATH)

app.include_router(meta_router, prefix=APP_BASE_PATH)
app.include_router(facade_compat_router)
