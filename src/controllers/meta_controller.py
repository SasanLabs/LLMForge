import httpx

from fastapi import APIRouter

from ..gateway_common import Prompt, OLLAMA_URL, DEFAULT_MODEL

router = APIRouter(prefix="/api/v1", tags=["meta"])


@router.get("/health")
async def health():
    return {"status": "ok"}


@router.post("/generate")
async def generate(p: Prompt):
    model = p.model or DEFAULT_MODEL
    async with httpx.AsyncClient() as client:
        resp = await client.post(
            f"{OLLAMA_URL}/api/chat",
            json={
                "model": model,
                "messages": [{"role": "user", "content": p.prompt}],
                "options": {"temperature": 0.2},
                "stream": False,
            },
            timeout=120,
        )
        if resp.status_code != 200:
            return {"error": f"Ollama returned {resp.status_code}", "details": resp.text}
        data = resp.json()
        return {"output": data.get("message", {}).get("content", "")}
