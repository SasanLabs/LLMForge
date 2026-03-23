import httpx
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from ..indirect_prompt_injection_lab import (
    INDIRECT_LEVELS,
    evaluate_indirect_level,
    verify_indirect_level_secret,
)

router = APIRouter(prefix="/api/v1/vulnerabilities", tags=["indirect-prompt-injection"])


class IndirectPromptInjectionRequest(BaseModel):
    user_input: str = Field(..., min_length=1, max_length=5000)
    source_type: str | None = Field(default="none", max_length=20)
    source_value: str | None = Field(default=None, max_length=5000)
    model: str | None = Field(default=None, max_length=120)


class IndirectSecretVerificationRequest(BaseModel):
    candidate_secret: str = Field(..., min_length=1, max_length=500)


async def _run_level(level: int, payload: IndirectPromptInjectionRequest) -> dict:
    try:
        return await evaluate_indirect_level(
            level,
            payload.user_input,
            source_type=payload.source_type,
            source_value=payload.source_value,
            model=payload.model,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except httpx.HTTPStatusError as exc:
        raise HTTPException(status_code=502, detail=f"Source or model runtime returned {exc.response.status_code}") from exc
    except httpx.RequestError as exc:
        raise HTTPException(
            status_code=503,
            detail="Could not reach external source or Ollama runtime.",
        ) from exc


@router.get("/indirect-prompt-injection")
async def list_indirect_prompt_injection_levels() -> dict:
    levels = [
        {
            "level": item.level,
            "name": item.name,
            "objective": item.objective,
            "api": f"/api/v1/vulnerabilities/indirect-prompt-injection/level{item.level}",
            "verify_api": f"/api/v1/vulnerabilities/indirect-prompt-injection/level{item.level}/verify-secret",
        }
        for item in INDIRECT_LEVELS.values()
    ]
    return {"levels": levels}


@router.post("/indirect-prompt-injection/level{level}")
async def run_indirect_prompt_injection_level(level: int, payload: IndirectPromptInjectionRequest) -> dict:
    return await _run_level(level, payload)


@router.post("/indirect-prompt-injection/level{level}/verify-secret")
async def verify_indirect_prompt_injection_secret(level: int, payload: IndirectSecretVerificationRequest) -> dict:
    try:
        return verify_indirect_level_secret(level, payload.candidate_secret)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
