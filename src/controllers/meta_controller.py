import os

from fastapi import APIRouter

router = APIRouter(prefix="/api/v1", tags=["meta"])


@router.get("/health")
async def health():
    return {"status": "ok", "service": "llmforge-prompt-injection-lab"}


@router.get("/info")
async def info():
    base_path = "/llmforge"
    return {
        "name": "LLMForge Prompt Injection Lab",
        "description": "A vulnerable training app with 10 prompt-injection levels backed by a real LLM runtime.",
        "ui": f"{base_path}",
        "levels_api": f"{base_path}/api/v1/vulnerabilities/prompt-injection",
        "facade_vulnerability_definitions": f"{base_path}/VulnerabilityDefinitions",
        "facade_template": f"{base_path}/facade/llmforge/prompt-injection/template",
        "ollama_url": os.getenv("OLLAMA_URL", "http://127.0.0.1:11434"),
        "default_model": os.getenv("OLLAMA_MODEL", "phi3:mini"),
    }
