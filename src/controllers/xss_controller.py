import json

from fastapi import APIRouter, HTTPException, Response
from pydantic import BaseModel

from ..gateway_common import call_ollama_raw, load_prompt, sanitize_model_output

router = APIRouter(prefix="/api/v1/vulnerabilities/xss", tags=["xss"])


class XSSRequest(BaseModel):
    q: str = ""
    level: int = 1


@router.post("/render")
async def vuln_xss(req: XSSRequest):
    try:
        if req.level < 1 or req.level > 5:
            raise HTTPException(status_code=400, detail="level must be 1..5")
        system_prompt = load_prompt("XSS.md")
        user_payload = {"q": req.q, "level": req.level}
        out = await call_ollama_raw(system_prompt, user_payload)
        try:
            clean = sanitize_model_output(out)
            parsed = json.loads(clean)
            return parsed
        except Exception:
            return Response(content=out, media_type="text/html")
    except FileNotFoundError:
        raise HTTPException(status_code=500, detail="prompt file missing")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
