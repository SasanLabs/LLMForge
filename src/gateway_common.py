from typing import Optional, Dict, Any
import os
import json

import httpx
from fastapi import HTTPException
from pydantic import BaseModel

# Ollama config
OLLAMA_URL = os.getenv("OLLAMA_URL", "http://ollama:11434")
DEFAULT_MODEL = os.getenv("OLLAMA_MODEL", "phi3:mini")


class Prompt(BaseModel):
    prompt: str
    model: Optional[str] = None


async def call_ollama_raw(system_prompt: str, user_payload: Dict[str, Any], model: str = DEFAULT_MODEL) -> str:
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


def load_prompt(name: str) -> str:
    """Load a prompt file from the vulnerabilities directory."""
    root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    path = os.path.join(root, "vulnerabilities", name)
    if not os.path.exists(path):
        raise FileNotFoundError(path)
    with open(path, "r", encoding="utf-8") as f:
        return f.read()


def sanitize_model_output(out: str) -> str:
    """Attempt to strip code fences and surrounding text, returning the first JSON object substring.

    Keeps behavior minimal: prefer extracting content between ```...``` if present, otherwise find first '{'..'}' balanced region.
    """
    if out is None:
        return ""
    s = out.strip()
    if s.startswith("```") and s.endswith("```"):
        parts = s.split("\n")
        if parts[0].startswith("```"):
            parts = parts[1:]
        if parts and parts[-1].endswith("```"):
            parts = parts[:-1]
        s = "\n".join(parts).strip()

    s = s.replace("```json", "").replace("```", "").strip()

    if "{" in s:
        start = s.find("{")
        depth = 0
        for i in range(start, len(s)):
            if s[i] == "{":
                depth += 1
            elif s[i] == "}":
                depth -= 1
                if depth == 0:
                    return s[start:i + 1]
    return s