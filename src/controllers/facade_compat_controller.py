import os
from pathlib import Path

from fastapi import APIRouter
from fastapi.responses import FileResponse, HTMLResponse

from ..framework import get_all_vulnerable_endpoints


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


def _build_vulnerability_definitions_from_framework() -> list[dict]:
    """Build vulnerability definitions from framework metadata."""
    # Import controller classes
    from .prompt_injection_controller import PromptInjectionController
    from .indirect_prompt_injection_controller import IndirectPromptInjectionController
    
    vulnerabilities = []
    
    # Process PromptInjectionController
    prompt_inj_meta = getattr(PromptInjectionController, "_vulnerable_llm_metadata", None)
    if prompt_inj_meta:
        levels = []
        for method_name in dir(PromptInjectionController):
            method = getattr(PromptInjectionController, method_name)
            method_levels = getattr(method, "_vulnerable_llm_levels", [])
            levels.extend(method_levels)
        
        level_defs = []
        for level in levels:
            level_number = level.get("level", "unknown")
            variant = level.get("variant").value if hasattr(level.get("variant"), "value") else level.get("variant", "UNSECURE")
            
            level_defs.append({
                "levelIdentifier": level_number,
                "variant": variant,
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
            })
        
        vulnerabilities.append({
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
            "levels": level_defs,
        })
    
    # Process IndirectPromptInjectionController
    indirect_inj_meta = getattr(IndirectPromptInjectionController, "_vulnerable_llm_metadata", None)
    if indirect_inj_meta:
        levels = []
        for method_name in dir(IndirectPromptInjectionController):
            method = getattr(IndirectPromptInjectionController, method_name)
            method_levels = getattr(method, "_vulnerable_llm_levels", [])
            levels.extend(method_levels)
        
        level_defs = []
        for level in levels:
            level_number = level.get("level", "unknown")
            variant = level.get("variant").value if hasattr(level.get("variant"), "value") else level.get("variant", "UNSECURE")
            
            level_defs.append({
                "levelIdentifier": level_number,
                "variant": variant,
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
            })
        
        vulnerabilities.append({
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
            "levels": level_defs,
        })
    
    return vulnerabilities


@router.get("/VulnerabilityDefinitions")
async def vulnerability_definitions() -> list[dict]:
    return _build_vulnerability_definitions_from_framework()


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


# Compatibility routes for old API
@router.post("/api/v1/vulnerabilities/prompt-injection/level{level}")
async def prompt_injection_level(level: str, request: Request) -> dict:
    """Handle old API calls for prompt injection levels."""
    from .prompt_injection_controller import PromptInjectionController
    controller = PromptInjectionController()
    
    # Map level_1 to level1 method, etc.
    method_name = f"level{level.replace('level_', '')}"
    if hasattr(controller, method_name):
        method = getattr(controller, method_name)
        return await method(request)
    else:
        return {"error": f"Level {level} not found"}


@router.post("/api/v1/vulnerabilities/indirect-prompt-injection/level{level}")
async def indirect_prompt_injection_level(level: str, request: Request) -> dict:
    """Handle old API calls for indirect prompt injection levels."""
    from .indirect_prompt_injection_controller import IndirectPromptInjectionController
    controller = IndirectPromptInjectionController()
    
    # Map level_1 to level1 method, etc.
    method_name = f"level{level.replace('level_', '')}"
    if hasattr(controller, method_name):
        method = getattr(controller, method_name)
        return await method(request)
    else:
        return {"error": f"Level {level} not found"}
