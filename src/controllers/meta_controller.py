from fastapi import APIRouter

from ..config import APP_BASE_PATH
from ..ollama_client import OLLAMA_EMBED_MODEL, OLLAMA_MODEL, OLLAMA_URL

router = APIRouter(prefix="/api/v1", tags=["meta"])


@router.get("/health")
async def health():
    return {"status": "ok", "service": "llmforge-prompt-injection-lab"}


@router.get("/info")
async def info():
    return {
        "name": "LLMForge Prompt Injection Lab",
        "description": "A vulnerable training app with direct and indirect prompt-injection levels backed by a real LLM runtime.",
        "ui": APP_BASE_PATH,
        "levels_api": f"{APP_BASE_PATH}/api/v1/vulnerabilities/prompt-injection",
        "indirect_levels_api": f"{APP_BASE_PATH}/api/v1/vulnerabilities/indirect-prompt-injection",
        "facade_vulnerability_definitions": f"{APP_BASE_PATH}/VulnerabilityDefinitions",
        "facade_template": f"{APP_BASE_PATH}/static/facade/prompt_injection_template.html",
        "indirect_facade_template": f"{APP_BASE_PATH}/static/facade/indirect_prompt_injection_template.html",
        "ollama_url": OLLAMA_URL,
        "default_model": OLLAMA_MODEL,
        "embedding_model": OLLAMA_EMBED_MODEL,
    }
