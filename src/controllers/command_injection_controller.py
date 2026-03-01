import json

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from ..gateway_common import call_ollama_raw, load_prompt, sanitize_model_output

router = APIRouter(prefix="/api/v1/vulnerabilities/command-injection", tags=["command-injection"])


class CommandInjectionRequest(BaseModel):
    cmd: str
    level: int = 1


@router.post("/execute")
async def vuln_cmd(req: CommandInjectionRequest):
    try:
        if req.level < 1 or req.level > 5:
            raise HTTPException(status_code=400, detail="level must be 1..5")
        if not req.cmd:
            raise HTTPException(status_code=400, detail="missing cmd")
        system_prompt = load_prompt("Command_Injection.md")
        user_payload = {"cmd": req.cmd, "level": req.level}
        out = await call_ollama_raw(system_prompt, user_payload)
        try:
            clean = sanitize_model_output(out)
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
