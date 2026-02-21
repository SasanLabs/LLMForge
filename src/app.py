from typing import Optional
import os
import httpx
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

# Use the service name defined in your docker-compose.yml
OLLAMA_URL = os.getenv("OLLAMA_URL", "http://ollama:11434")
DEFAULT_MODEL = os.getenv("OLLAMA_MODEL", "mistral")

app = FastAPI(title="LLMForge Gateway")

class Prompt(BaseModel):
    prompt: str
    model: Optional[str] = None

@app.get("/health")
async def health():
    return {"status": "ok"}
@app.post("/generate")
async def generate(p: Prompt):
    model = p.model or DEFAULT_MODEL
    async with httpx.AsyncClient() as client:
        resp = await client.post(
            f"{OLLAMA_URL}/api/chat",
            json={
                "model": model,
                "messages": [{"role": "user", "content": p.prompt}],
                "options": {"temperature": 0.2},
                "stream": False,  # ADD THIS LINE
            },
            timeout=120, # Models can take a minute to load into RAM
        )
        if resp.status_code != 200:
             return {"error": f"Ollama returned {resp.status_code}", "details": resp.text}
             
        data = resp.json()
        return {"output": data.get("message", {}).get("content", "")}