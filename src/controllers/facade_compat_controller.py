from fastapi import APIRouter

from ..config import APP_BASE_PATH
from ..framework import get_facade_vulnerability_definitions


router = APIRouter(prefix=APP_BASE_PATH, tags=["facade-compat"])


@router.get("/VulnerabilityDefinitions")
async def vulnerability_definitions() -> list[dict]:
    return get_facade_vulnerability_definitions()
