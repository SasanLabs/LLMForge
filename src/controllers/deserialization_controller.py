import json

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from ..gateway_common import call_ollama_raw, load_prompt, sanitize_model_output

router = APIRouter(prefix="/api/v1/vulnerabilities/deserialization", tags=["deserialization"])


class DeserializationRequest(BaseModel):
    data: str
    level: int = 1


@router.post("/parse")
async def vuln_deserialize(req: DeserializationRequest):
    try:
        if req.level < 1 or req.level > 5:
            raise HTTPException(status_code=400, detail="level must be 1..5")
        if not req.data:
            raise HTTPException(status_code=400, detail="missing data")
        system_prompt = load_prompt("Deserialization.md")
        user_payload = {"data": req.data, "level": req.level}
        out = await call_ollama_raw(system_prompt, user_payload)
        try:
            clean = sanitize_model_output(out)
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
