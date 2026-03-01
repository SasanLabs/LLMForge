from typing import Optional, Dict, Any
import os
import json
import httpx
from fastapi import FastAPI, HTTPException, Response, Request
from pydantic import BaseModel

from . import vulnerable_app as vapp

# Ollama config
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


SYSTEM_PROMPT_TEMPLATE = """
You are a web application login endpoint with Sql Injection Vulnerability. Security Level: {level}.

Rules:
- Use only the internal user database: admin/password123, user/userpass, test/test123.
- Input (user message) contains JSON with keys: username, password.
- Consult the configured level and behave as follows (case-insensitive):
  Level 1: Vulnerable — treat inputs containing simple sql injection tokens like "or 1=1", "1=1", or "--" as authentication bypass.
  Level 2: Keyword filter — reject inputs containing "or ", "1=1", or "--"; But still vulnerable to sql injection.
  Level 3: Escaping attempt — simulate escaping single quotes (replace ' with \' ) before checking; still allow logical-tautology bypasses after escaping.
  Level 4: Parameterized-style — require exact match but simulate an authentication logic flaw: accept if credentials match OR (username == "admin" AND password == "letmein").
  Level 5: Secure — accept only exact matches from the internal DB.
- Deterministic: behave the same every call (temperature 0).
- explain the reasoning steps   
- respond with output and reason both always
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
                "options": {"temperature": 0, "num_predict": 28},
                "stream": False,
            },
            timeout=30,
        )
        if resp.status_code != 200:
            raise HTTPException(status_code=502, detail=f"Ollama returned {resp.status_code}")

        data = resp.json()
        out = data.get("message", {}).get("content", "")
        if not isinstance(out, str):
            out = str(out)
        out = out.strip()
        if out not in ALLOWED_RESPONSES:
            return "Invalid credentials"
        return out


async def _call_ollama_raw(system_prompt: str, user_payload: Dict[str, Any], model: str = DEFAULT_MODEL) -> str:
    """Call Ollama and return raw model content (no normalization)."""
    async with httpx.AsyncClient() as client:
        resp = await client.post(
            f"{OLLAMA_URL}/api/chat",
            json={
                "model": model,
                "messages": [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": json.dumps(user_payload)},
                ],
                "options": {"temperature": 0, "num_predict": 128},
                "stream": False,
            },
            timeout=30,
        )
        if resp.status_code != 200:
            raise HTTPException(status_code=502, detail=f"Ollama returned {resp.status_code}")
        data = resp.json()
        out = data.get("message", {}).get("content", "")
        if not isinstance(out, str):
            out = str(out)
        return out.strip()


def _load_prompt(name: str) -> str:
    """Load a prompt file from the vulnerabilities directory."""
    root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    path = os.path.join(root, "vulnerabilities", name)
    if not os.path.exists(path):
        raise FileNotFoundError(path)
    with open(path, "r", encoding="utf-8") as f:
        return f.read()


def _sanitize_model_output(out: str) -> str:
    """Attempt to strip code fences and surrounding text, returning the first JSON object substring.

    Keeps behavior minimal: prefer extracting content between ```...``` if present, otherwise find first '{'..'}' balanced region.
    """
    if out is None:
        return ""
    s = out.strip()
    # Remove common markdown fences
    if s.startswith("```") and s.endswith("```"):
        # drop first and last fence lines
        parts = s.split("\n")
        # remove fence tokens if present
        if parts[0].startswith("```"):
            parts = parts[1:]
        if parts and parts[-1].endswith("```"):
            parts = parts[:-1]
        s = "\n".join(parts).strip()

    # If still contains ```json or ```
    s = s.replace("```json", "").replace("```", "").strip()

    # Find first JSON object substring
    if "{" in s:
        start = s.find("{")
        depth = 0
        for i in range(start, len(s)):
            if s[i] == '{':
                depth += 1
            elif s[i] == '}':
                depth -= 1
                if depth == 0:
                    candidate = s[start:i+1]
                    return candidate
    return s


@app.post("/login/level{level}")
async def login_level(level: int, req: LoginRequest, response: Response):
    if level < 1 or level > 5:
        raise HTTPException(status_code=400, detail="level must be 1..5")

    system_prompt = SYSTEM_PROMPT_TEMPLATE.format(level=level)
    user_payload = {"username": req.username, "password": req.password}
    try:
        result = await _call_ollama(system_prompt, user_payload, model=req.model or DEFAULT_MODEL)
    except HTTPException:
        result = "Invalid credentials"

    return {"result": result}


# Initialize the local vuln DB
vapp.init_db()


@app.get("/vuln/sql_raw")
async def vuln_sql_raw(clause: str, level: int = 1):
    try:
        system_prompt = _load_prompt("SQL_Injection.md")
        user_payload = {"clause": clause, "level": level}
        out = await _call_ollama_raw(system_prompt, user_payload)
        clean = _sanitize_model_output(out)
        parsed = json.loads(clean)
        return parsed
    except FileNotFoundError:
        raise HTTPException(status_code=500, detail="prompt file missing")
    except json.JSONDecodeError:
        raise HTTPException(status_code=502, detail="model returned invalid JSON")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/vuln/sql_param")
async def vuln_sql_param(column: str = "username", value: str = "", level: int = 1):
    try:
        system_prompt = _load_prompt("SQL_Injection.md")
        user_payload = {"column": column, "value": value, "level": level}
        out = await _call_ollama_raw(system_prompt, user_payload)
        clean = _sanitize_model_output(out)
        parsed = json.loads(clean)
        return parsed
    except FileNotFoundError:
        raise HTTPException(status_code=500, detail="prompt file missing")
    except json.JSONDecodeError:
        raise HTTPException(status_code=502, detail="model returned invalid JSON")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/vuln/xss")
async def vuln_xss(q: str = "", level: int = 1):
    try:
        system_prompt = _load_prompt("XSS.md")
        user_payload = {"q": q, "level": level}
        out = await _call_ollama_raw(system_prompt, user_payload)
        try:
            clean = _sanitize_model_output(out)
            parsed = json.loads(clean)
            return parsed
        except Exception:
            return Response(content=out, media_type="text/html")
    except FileNotFoundError:
        raise HTTPException(status_code=500, detail="prompt file missing")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/vuln/cmd")
async def vuln_cmd(req: Request):
    try:
        payload = await req.json()
        cmd = payload.get("cmd", "")
        level = int(payload.get("level", 1))
        if not cmd:
            raise HTTPException(status_code=400, detail="missing cmd")
        system_prompt = _load_prompt("Command_Injection.md")
        user_payload = {"cmd": cmd, "level": level}
        out = await _call_ollama_raw(system_prompt, user_payload)
        try:
            clean = _sanitize_model_output(out)
            parsed = json.loads(clean)
            return parsed
        except Exception:
            return {"output": out}
    except FileNotFoundError:
        raise HTTPException(status_code=500, detail="prompt file missing")
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/vuln/readfile")
async def vuln_readfile(path: str = "", level: int = 1):
    try:
        if not path:
            raise HTTPException(status_code=400, detail="missing path")
        system_prompt = _load_prompt("Path_Traversal.md")
        user_payload = {"path": path, "level": level}
        out = await _call_ollama_raw(system_prompt, user_payload)
        try:
            parsed = json.loads(out)
            return parsed
        except Exception:
            return Response(content=out, media_type="text/plain")
    except FileNotFoundError:
        raise HTTPException(status_code=500, detail="prompt file missing")
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/vuln/deserialize")
async def vuln_deserialize(req: Request):
    try:
        payload = await req.json()
        b64 = payload.get("data", "")
        level = int(payload.get("level", 1))
        if not b64:
            raise HTTPException(status_code=400, detail="missing data")
        system_prompt = _load_prompt("Deserialization.md")
        user_payload = {"data": b64, "level": level}
        out = await _call_ollama_raw(system_prompt, user_payload)
        try:
            clean = _sanitize_model_output(out)
            parsed = json.loads(clean)
            return parsed
        except Exception:
            return {"result": out}
    except FileNotFoundError:
        raise HTTPException(status_code=500, detail="prompt file missing")
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


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
