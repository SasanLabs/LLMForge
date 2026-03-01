import json

from fastapi import APIRouter, HTTPException, Response
from pydantic import BaseModel

from ..gateway_common import call_ollama_raw, load_prompt

router = APIRouter(prefix="/api/v1/vulnerabilities/path-traversal", tags=["path-traversal"])


class PathTraversalRequest(BaseModel):
    path: str
    level: int = 1


@router.post("/read")
async def vuln_readfile(req: PathTraversalRequest):
    try:
        if req.level < 1 or req.level > 5:
            raise HTTPException(status_code=400, detail="level must be 1..5")
        if not req.path:
            raise HTTPException(status_code=400, detail="missing path")
        system_prompt = load_prompt("Path_Traversal.md")
        user_payload = {"path": req.path, "level": req.level}
        out = await call_ollama_raw(system_prompt, user_payload)
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
