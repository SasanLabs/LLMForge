import os

from fastapi import APIRouter

router = APIRouter(prefix="/api/v1", tags=["meta"])


@router.get("/health")
async def health():
    return {"status": "ok", "service": "llmforge-prompt-injection-lab"}


@router.get("/info")
async def info():
    return {
        "name": "LLMForge Prompt Injection Lab",
        "description": "A vulnerable training app with 8 prompt-injection levels backed by a real LLM runtime.",
        "ui": "/",
        "levels_api": "/api/v1/vulnerabilities/prompt-injection",
        "ollama_url": os.getenv("OLLAMA_URL", "http://127.0.0.1:11434"),
        "default_model": os.getenv("OLLAMA_MODEL", "phi3:mini"),
    }
