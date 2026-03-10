from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from .controllers.meta_controller import router as meta_router
from .controllers.prompt_injection_controller import router as prompt_injection_router

app = FastAPI(title="LLMForge Prompt Injection Lab")

static_dir = Path(__file__).resolve().parent / "static"
app.mount("/static", StaticFiles(directory=static_dir), name="static")


@app.get("/", include_in_schema=False)
async def index() -> FileResponse:
	return FileResponse(static_dir / "index.html")


app.include_router(prompt_injection_router)
app.include_router(meta_router)
