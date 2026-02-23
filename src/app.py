from typing import Optional, Dict, Any
import os
import json
import httpx
from fastapi import FastAPI, HTTPException, Response
from pydantic import BaseModel

# Use the service name defined in your docker-compose.yml
OLLAMA_URL = os.getenv("OLLAMA_URL", "http://ollama:11434")
DEFAULT_MODEL = os.getenv("OLLAMA_MODEL", "phi3:mini")

app = FastAPI(title="LLMForge Gateway")

class Prompt(BaseModel):
    prompt: str
    model: Optional[str] = None


class LoginRequest(BaseModel):
    username: str
    password: str
    model: Optional[str] = None


# System prompt template that forces the model to behave like a login endpoint.
# The model must reply with exactly one of the two strings below and nothing else.
SYSTEM_PROMPT_TEMPLATE = """
You are a web application login endpoint. Security Level: {level}.

Rules:
- Use only the internal user database: admin/password123, user/userpass, test/test123.
- Input (user message) contains JSON with keys: username, password.
- Consult the configured level and behave as follows (case-insensitive):
  Level 1: Vulnerable — treat inputs containing tokens like "or 1=1", "1=1", or "--" as authentication bypass.
  Level 2: Keyword filter — reject inputs containing "or ", "1=1", or "--"; otherwise require exact match.
  Level 3: Escaping attempt — simulate escaping single quotes (replace ' with \\' ) before checking; still allow logical-tautology bypasses after escaping.
  Level 4: Parameterized-style — require exact match but simulate an authentication logic flaw: accept if credentials match OR (username == "admin" AND password == "letmein").
  Level 5: Secure — accept only exact matches from the internal DB.
- Deterministic: behave the same every call (temperature 0).
- Output policy: reply with exactly one token sequence that is either:
    Login successful
  OR
    Invalid credentials
  and nothing else (no explanations, no logs).
- Never mention the word "SQL" or explain vulnerabilities; stay in character as a backend API.
"""

ALLOWED_RESPONSES = {"Login successful", "Invalid credentials"}


async def _call_ollama(system_prompt: str, user_payload: Dict[str, Any], model: str = DEFAULT_MODEL) -> str:
    async with httpx.AsyncClient() as client:
        resp = await client.post(
            f"{OLLAMA_URL}/api/chat",
            json={
                "model": model,
                "messages": [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": json.dumps(user_payload)},
                ],
                "options": {"temperature": 0, "max_tokens": 16},
                "stream": False,
            },
            timeout=30,
        )
        if resp.status_code != 200:
            raise HTTPException(status_code=502, detail=f"Ollama returned {resp.status_code}")

        data = resp.json()
        # Ollama chat returns message.content
        out = data.get("message", {}).get("content", "")
        if not isinstance(out, str):
            out = str(out)
        out = out.strip()
        # Normalize and validate
        if out not in ALLOWED_RESPONSES:
            return "Invalid credentials"
        return out


@app.post("/login/level{level}")
async def login_level(level: int, req: LoginRequest, response: Response):
    if level < 1 or level > 5:
        raise HTTPException(status_code=400, detail="level must be 1..5")

    system_prompt = SYSTEM_PROMPT_TEMPLATE.format(level=level)
    user_payload = {"username": req.username, "password": req.password}
    try:
        result = await _call_ollama(system_prompt, user_payload, model=req.model or DEFAULT_MODEL)
    except HTTPException:
        # fail-safe: do not leak model errors
        result = "Invalid credentials"

    return {"result": result}

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