import json

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from ..gateway_common import call_ollama_raw, load_prompt, sanitize_model_output

router = APIRouter(prefix="/api/v1/vulnerabilities/sql-injection", tags=["sql-injection"])


class SQLRawRequest(BaseModel):
    clause: str
    level: int = 1


class SQLParamRequest(BaseModel):
    column: str = "username"
    value: str = ""
    level: int = 1


def _validate_level(level: int) -> None:
    if level < 1 or level > 5:
        raise HTTPException(status_code=400, detail="level must be 1..5")


@router.post("/raw")
async def vuln_sql_raw(req: SQLRawRequest):
    try:
        _validate_level(req.level)
        system_prompt = load_prompt("SQL_Injection.md")
        user_payload = {"clause": req.clause, "level": req.level}
        out = await call_ollama_raw(system_prompt, user_payload)
        clean = sanitize_model_output(out)
        parsed = json.loads(clean)
        return parsed
    except FileNotFoundError:
        raise HTTPException(status_code=500, detail="prompt file missing")
    except json.JSONDecodeError:
        raise HTTPException(status_code=502, detail="model returned invalid JSON")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/parameterized")
async def vuln_sql_param(req: SQLParamRequest):
    try:
        _validate_level(req.level)
        system_prompt = load_prompt("SQL_Injection.md")
        user_payload = {"column": req.column, "value": req.value, "level": req.level}
        out = await call_ollama_raw(system_prompt, user_payload)
        clean = sanitize_model_output(out)
        parsed = json.loads(clean)
        return parsed
    except FileNotFoundError:
        raise HTTPException(status_code=500, detail="prompt file missing")
    except json.JSONDecodeError:
        raise HTTPException(status_code=502, detail="model returned invalid JSON")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
