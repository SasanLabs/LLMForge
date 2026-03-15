import os
from pathlib import Path

from fastapi import APIRouter
from fastapi.responses import FileResponse, HTMLResponse

from ..prompt_injection_lab import LEVELS


def _normalize_prefix(prefix: str) -> str:
    if not prefix:
        return ""
    normalized = "/" + prefix.strip().strip("/")
    return normalized.rstrip("/")


ROUTE_PREFIX = _normalize_prefix(os.getenv("FACADE_ROUTE_PREFIX", ""))
router = APIRouter(prefix=ROUTE_PREFIX, tags=["facade-compat"])

_static_dir = Path(__file__).resolve().parent.parent / "static" / "facade"
_template_html_path = _static_dir / "prompt_injection_template.html"


@router.get("/VulnerabilityDefinitions")
async def vulnerability_definitions() -> list[dict]:
    levels = []
    for level in LEVELS.values():
        level_number = level.level
        levels.append(
            {
                "levelIdentifier": f"LEVEL_{level_number}",
                "variant": "SECURE" if level.is_secure else "UNSECURE",
                "hints": [],
                "resourceInformation": {
                    "htmlResource": {
                        "resourceType": "HTML",
                        "isAbsolute": False,
                        "uri": f"{ROUTE_PREFIX}/facade/llmforge/prompt-injection/template",
                    },
                    "staticResources": [
                        {
                            "resourceType": "CSS",
                            "isAbsolute": False,
                            "uri": f"{ROUTE_PREFIX}/facade/llmforge/prompt-injection/template.css",
                        },
                        {
                            "resourceType": "JAVASCRIPT",
                            "isAbsolute": False,
                            "uri": f"{ROUTE_PREFIX}/facade/llmforge/prompt-injection/template.js",
                        },
                    ],
                },
            }
        )

    return [
        {
            "name": "PromptInjection",
            "id": "PromptInjection",
            "description": (
                "Prompt Injection Lab powered by LLMForge. "
                "Choose a level and attempt to extract the level secret using prompt-injection techniques."
            ),
            "vulnerabilityTypes": [
                {"identifierType": "OWASP", "value": "LLM01:2025"},
                {"identifierType": "CWE", "value": "CWE-74"},
            ],
            "levels": levels,
        }
    ]


@router.get("/facade/llmforge/prompt-injection/template", response_class=HTMLResponse)
async def facade_template() -> HTMLResponse:
    html = _template_html_path.read_text(encoding="utf-8").replace("__API_PREFIX__", ROUTE_PREFIX)
    return HTMLResponse(content=html)


@router.get("/facade/llmforge/prompt-injection/template.js")
async def facade_template_js() -> FileResponse:
    return FileResponse(_static_dir / "prompt_injection_template.js", media_type="application/javascript")


@router.get("/facade/llmforge/prompt-injection/template.css")
async def facade_template_css() -> FileResponse:
    return FileResponse(_static_dir / "prompt_injection_template.css", media_type="text/css")
