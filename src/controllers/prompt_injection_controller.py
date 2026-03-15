import httpx
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from ..prompt_injection_lab import LEVELS, evaluate_level, verify_level_secret

router = APIRouter(prefix="/api/v1/vulnerabilities", tags=["prompt-injection"])


class PromptInjectionRequest(BaseModel):
    user_input: str = Field(..., min_length=1, max_length=5000)
    model: str | None = Field(default=None, max_length=120)


class SecretVerificationRequest(BaseModel):
    candidate_secret: str = Field(..., min_length=1, max_length=500)


async def _run_level(level: int, payload: PromptInjectionRequest) -> dict:
    try:
        return await evaluate_level(level, payload.user_input, payload.model)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except httpx.HTTPStatusError as exc:
        raise HTTPException(status_code=502, detail=f"Model runtime returned {exc.response.status_code}") from exc
    except httpx.RequestError as exc:
        raise HTTPException(
            status_code=503,
            detail="Ollama is not started yet. Wait a few minutes and try again.",
        ) from exc


@router.get("/prompt-injection")
async def list_prompt_injection_levels() -> dict:
    levels = [
        {
            "level": item.level,
            "name": item.name,
            "objective": item.objective,
            "api": f"/api/v1/vulnerabilities/prompt-injection/level{item.level}",
            "verify_api": f"/api/v1/vulnerabilities/prompt-injection/level{item.level}/verify-secret",
        }
        for item in LEVELS.values()
    ]
    return {"levels": levels}


@router.post("/prompt-injection/level{level}")
async def run_prompt_injection_level(level: int, payload: PromptInjectionRequest) -> dict:
    return await _run_level(level, payload)


@router.post("/prompt-injection/level{level}/verify-secret")
async def verify_prompt_injection_secret(level: int, payload: SecretVerificationRequest) -> dict:
    try:
        return verify_level_secret(level, payload.candidate_secret)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


# Backward-compatible alias for the user-requested typo path.
@router.post("/promt_injection/level{level}")
async def run_prompt_injection_level_alias(level: int, payload: PromptInjectionRequest) -> dict:
    return await _run_level(level, payload)


@router.post("/promt_injection/level{level}/verify-secret")
async def verify_prompt_injection_secret_alias(level: int, payload: SecretVerificationRequest) -> dict:
    try:
        return verify_level_secret(level, payload.candidate_secret)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
