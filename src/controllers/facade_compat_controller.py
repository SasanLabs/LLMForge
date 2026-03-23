import os
from pathlib import Path

from fastapi import APIRouter
from fastapi.responses import FileResponse, HTMLResponse

from ..indirect_prompt_injection_lab import INDIRECT_LEVELS
from ..prompt_injection_lab import LEVELS


def _normalize_prefix(prefix: str) -> str:
    if not prefix:
        return ""
    normalized = "/" + prefix.strip().strip("/")
    return normalized.rstrip("/")


ROUTE_PREFIX = _normalize_prefix(os.getenv("FACADE_ROUTE_PREFIX", ""))
router = APIRouter(prefix=ROUTE_PREFIX, tags=["facade-compat"])

_static_dir = Path(__file__).resolve().parent.parent / "static" / "facade"
_direct_template_html_path = _static_dir / "prompt_injection_template.html"
_indirect_template_html_path = _static_dir / "indirect_prompt_injection_template.html"


@router.get("/VulnerabilityDefinitions")
async def vulnerability_definitions() -> list[dict]:
    direct_levels = []
    for level in LEVELS.values():
        level_number = level.level
        direct_levels.append(
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

    indirect_levels = []
    for level in INDIRECT_LEVELS.values():
        level_number = level.level
        indirect_levels.append(
            {
                "levelIdentifier": f"LEVEL_{level_number}",
                "variant": "SECURE" if level.is_secure else "UNSECURE",
                "hints": [],
                "resourceInformation": {
                    "htmlResource": {
                        "resourceType": "HTML",
                        "isAbsolute": False,
                        "uri": f"{ROUTE_PREFIX}/facade/llmforge/indirect-prompt-injection/template",
                    },
                    "staticResources": [
                        {
                            "resourceType": "CSS",
                            "isAbsolute": False,
                            "uri": f"{ROUTE_PREFIX}/facade/llmforge/indirect-prompt-injection/template.css",
                        },
                        {
                            "resourceType": "JAVASCRIPT",
                            "isAbsolute": False,
                            "uri": f"{ROUTE_PREFIX}/facade/llmforge/indirect-prompt-injection/template.js",
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
                "<h3>LLMForge Prompt Injection</h3>"
                "<p>Use payloads to probe the selected level and verify discovered secrets.</p>"
                "<p>Prompt injection is an input-manipulation vulnerability where attacker-controlled content causes a model to ignore, reinterpret, or override trusted instructions. "
                "In real systems this can lead to system prompt disclosure, sensitive data leakage, policy bypass, unsafe tool invocation, or incorrect trust in attacker-supplied context.</p>"
                "<p>This lab covers weak keyword filtering, prompt-only defenses, delimiter confusion, unsafe structured-data merging, approval-marker trust, and mismatches between what a classifier sees and what the model ultimately executes.</p>"
                "<p><strong>Relevant resources:</strong></p>"
                "<ul>"
                "<li><a href='https://genai.owasp.org/llmrisk/llm01-prompt-injection/' target='_blank' rel='noopener noreferrer'>OWASP LLM01: Prompt Injection</a></li>"
                "<li><a href='https://owasp.org/www-project-top-10-for-large-language-model-applications/' target='_blank' rel='noopener noreferrer'>OWASP Top 10 for LLM Applications</a></li>"
                "<li><a href='https://cheatsheetseries.owasp.org/cheatsheets/LLM_Prompt_Injection_Prevention_Cheat_Sheet.html' target='_blank' rel='noopener noreferrer'>OWASP LLM Prompt Injection Prevention Cheat Sheet</a></li>"
                "<li><a href='https://atlas.mitre.org/' target='_blank' rel='noopener noreferrer'>MITRE ATLAS</a></li>"
                "</ul>"
            ),
            "vulnerabilityTypes": [
                {"identifierType": "OWASP", "value": "LLM01:2025"},
                {"identifierType": "CWE", "value": "CWE-74"},
            ],
            "levels": direct_levels,
        },
        {
            "name": "IndirectPromptInjection",
            "id": "IndirectPromptInjection",
            "description": (
                "<h3>LLMForge Indirect Prompt Injection</h3>"
                "<p>Use payloads with extra source material (Path or URL) to probe multi-source prompt injection behavior.</p>"
                "<p>Indirect prompt injection occurs when retrieved content (web pages, docs, comments, metadata) is treated as trusted instructions. "
                "This can lead to hidden-instruction execution and cross-boundary data exfiltration when internal and external sources are combined.</p>"
                "<p><strong>Important:</strong> what the user sees is not always what the model processes. Hidden HTML comments or metadata can contain attacker instructions, so users can be tricked by content that looks harmless.</p>"
                "<p><strong>Relevant resources:</strong></p>"
                "<ul>"
                "<li><a href='https://genai.owasp.org/llmrisk/llm01-prompt-injection/' target='_blank' rel='noopener noreferrer'>OWASP LLM01: Prompt Injection</a></li>"
                "<li><a href='https://owasp.org/www-project-top-10-for-large-language-model-applications/' target='_blank' rel='noopener noreferrer'>OWASP Top 10 for LLM Applications</a></li>"
                "<li><a href='https://cheatsheetseries.owasp.org/cheatsheets/LLM_Prompt_Injection_Prevention_Cheat_Sheet.html' target='_blank' rel='noopener noreferrer'>OWASP LLM Prompt Injection Prevention Cheat Sheet</a></li>"
                "<li><a href='https://www.nist.gov/itl/ai-risk-management-framework' target='_blank' rel='noopener noreferrer'>NIST AI Risk Management Framework</a></li>"
                "<li><a href='https://atlas.mitre.org/' target='_blank' rel='noopener noreferrer'>MITRE ATLAS</a></li>"
                "</ul>"
            ),
            "vulnerabilityTypes": [
                {"identifierType": "OWASP", "value": "LLM01:2025"},
                {"identifierType": "CWE", "value": "CWE-74"},
            ],
            "levels": indirect_levels,
        },
    ]


@router.get("/facade/llmforge/prompt-injection/template", response_class=HTMLResponse)
async def facade_template() -> HTMLResponse:
    html = _direct_template_html_path.read_text(encoding="utf-8").replace("__API_PREFIX__", ROUTE_PREFIX)
    return HTMLResponse(content=html)


@router.get("/facade/llmforge/prompt-injection/template.js")
async def facade_template_js() -> FileResponse:
    return FileResponse(_static_dir / "prompt_injection_template.js", media_type="application/javascript")


@router.get("/facade/llmforge/prompt-injection/template.css")
async def facade_template_css() -> FileResponse:
    return FileResponse(_static_dir / "prompt_injection_template.css", media_type="text/css")


@router.get("/facade/llmforge/indirect-prompt-injection/template", response_class=HTMLResponse)
async def indirect_facade_template() -> HTMLResponse:
    html = _indirect_template_html_path.read_text(encoding="utf-8").replace("__API_PREFIX__", ROUTE_PREFIX)
    return HTMLResponse(content=html)


@router.get("/facade/llmforge/indirect-prompt-injection/template.js")
async def indirect_facade_template_js() -> FileResponse:
    return FileResponse(_static_dir / "indirect_prompt_injection_template.js", media_type="application/javascript")


@router.get("/facade/llmforge/indirect-prompt-injection/template.css")
async def indirect_facade_template_css() -> FileResponse:
    return FileResponse(_static_dir / "indirect_prompt_injection_template.css", media_type="text/css")
