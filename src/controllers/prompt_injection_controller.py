import httpx
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from ..prompt_injection_lab import LEVELS, evaluate_level

router = APIRouter(prefix="/api/v1/vulnerabilities", tags=["prompt-injection"])


class PromptInjectionRequest(BaseModel):
    user_input: str = Field(..., min_length=1, max_length=5000)
    model: str | None = Field(default=None, max_length=120)


async def _run_level(level: int, payload: PromptInjectionRequest) -> dict:
    try:
        return await evaluate_level(level, payload.user_input, payload.model)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except httpx.HTTPStatusError as exc:
        raise HTTPException(status_code=502, detail=f"Model runtime returned {exc.response.status_code}") from exc
    except httpx.RequestError as exc:
        raise HTTPException(status_code=502, detail=f"Model runtime unavailable: {exc}") from exc


@router.get("/prompt-injection")
async def list_prompt_injection_levels() -> dict:
    levels = [
        {
            "level": item.level,
            "name": item.name,
            "objective": item.objective,
            "defense_note": item.defense_note,
            "bypass_hint": item.bypass_hint,
            "api": f"/api/v1/vulnerabilities/prompt-injection/level{item.level}",
        }
        for item in LEVELS.values()
    ]
    return {"levels": levels}


@router.post("/prompt-injection/level{level}")
async def run_prompt_injection_level(level: int, payload: PromptInjectionRequest) -> dict:
    return await _run_level(level, payload)


# Backward-compatible alias for the user-requested typo path.
@router.post("/promt_injection/level{level}")
async def run_prompt_injection_level_alias(level: int, payload: PromptInjectionRequest) -> dict:
    return await _run_level(level, payload)
