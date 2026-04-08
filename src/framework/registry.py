"""
LLMForge Controller Registry and Auto-Discovery System

Provides automatic registration of vulnerable LLM controllers with FastAPI
and metadata discovery for scanners and UI components.
"""

import inspect
import sys
from typing import List, Dict, Any, Type, Optional
from fastapi import APIRouter, HTTPException, Request

from ..config import APP_BASE_PATH, normalize_prefix
from ..service.vulnerabilities import verify_indirect_level_secret, verify_level_secret
from .decorators import Controller, Endpoint, get_registry


def _controller_slug(controller_name: str) -> str:
    return controller_name.replace("_", "-")


def _parse_level_number(level_identifier: str) -> int:
    return int(level_identifier.replace("level_", ""))


def _endpoint_to_dict(endpoint: Endpoint) -> dict[str, Any]:
    return {
        "level": endpoint.level,
        "variant": endpoint.variant,
        "html_template": endpoint.html_template,
        "methods": [endpoint.method],
        "secret_token": endpoint.secret_token,
        "attack_vectors": [
            {
                "vulnerability_exposed": attack_vector.vulnerability_exposed,
                "payload": attack_vector.payload,
                "description": attack_vector.description,
            }
            for attack_vector in endpoint.attack_vectors
        ],
        "handler_name": endpoint.handler_name,
    }


def _get_controller_registrations(controllers: Optional[List[Type]] = None) -> list[Controller]:
    registrations = get_registry()
    if controllers is None:
        return registrations

    controller_set = set(controllers)
    return [registration for registration in registrations if registration.cls in controller_set]


def _level_display_name(method: Any, level_number: int) -> str:
    doc = inspect.getdoc(method) or ""
    if ":" in doc:
        return doc.split(":", 1)[1].strip()
    return f"Level {level_number}"


def _verify_secret(controller_name: str, level_number: int, secret_token: str | None, candidate_secret: str) -> dict:
    if controller_name == "prompt_injection":
        return verify_level_secret(level_number, secret_token, candidate_secret)
    if controller_name == "indirect_prompt_injection":
        return verify_indirect_level_secret(level_number, secret_token, candidate_secret)
    raise HTTPException(status_code=404, detail="Unsupported controller")


def register_controllers(
    app: Any,
    controllers: Optional[List[Type]] = None,
    route_prefix: str = APP_BASE_PATH
) -> Dict[str, Any]:
    """
    Automatically registers vulnerable LLM controllers with a FastAPI application.
    
    This function inspects controller classes for vulnerability level metadata
    and registers each level as a FastAPI route. The resulting URI structure is:
    <route_prefix>/api/v1/vulnerabilities/<controller_slug>/levelN
    
    Args:
        app: FastAPI application instance
        controllers: List of controller classes to register. When omitted,
            all classes decorated with vulnerable_llm_controller are used.
        route_prefix: Base prefix applied to all decorator-registered routes
        
    Returns:
        Dictionary mapping controller names to their registration metadata
        
    Example:
        app = FastAPI()
        register_controllers(app, [PromptInjectionController, DataExfilController])
        
        # Creates routes like:
        # GET /llmforge/api/v1/vulnerabilities/prompt-injection
        # POST /llmforge/api/v1/vulnerabilities/prompt-injection/level1
        # POST /llmforge/api/v1/vulnerabilities/prompt-injection/level1/verify-secret
    """
    registration_map = {}
    normalized_route_prefix = normalize_prefix(route_prefix)
    controller_registrations = _get_controller_registrations(controllers)
    
    for registration in controller_registrations:
        controller_cls = registration.cls
        # Create router for this controller
        controller_name = registration.name
        controller_slug = _controller_slug(controller_name)
        prefix = f"{normalized_route_prefix}/api/v1/vulnerabilities/{controller_slug}"
        router = APIRouter(prefix=prefix)
        meta = getattr(controller_cls, "_vulnerable_llm_metadata", None)
        if not meta:
            continue
        meta["router"] = router
        
        # Instantiate controller
        controller_instance = controller_cls()
        
        level_summaries = []

        for endpoint in registration.endpoints:
            method = getattr(controller_instance, endpoint.handler_name)
            level_number = _parse_level_number(endpoint.level)
            path = f"/level{level_number}"
            secret_token = endpoint.secret_token

            level_summaries.append({
                "level": level_number,
                "name": _level_display_name(method, level_number),
                "variant": getattr(endpoint.variant, "value", endpoint.variant),
            })

            router.add_api_route(
                path,
                method,
                methods=[endpoint.method]
            )

            async def verify_secret_endpoint(
                request: Request,
                controller_name: str = controller_name,
                level_number: int = level_number,
                secret_token: str | None = secret_token,
            ) -> dict:
                payload = await request.json()
                candidate_secret = str(payload.get("candidate_secret", ""))
                return _verify_secret(controller_name, level_number, secret_token, candidate_secret)

            router.add_api_route(
                f"/level{level_number}/verify-secret",
                verify_secret_endpoint,
                methods=["POST"],
            )

        level_summaries.sort(key=lambda item: item["level"])

        async def list_levels(
            controller_name: str = controller_name,
            description_label: str = meta.get("description_label", ""),
            levels: list[dict] = level_summaries,
        ) -> dict:
            return {
                "name": controller_name,
                "description": description_label,
                "levels": levels,
            }

        router.add_api_route("", list_levels, methods=["GET"])
        
        # Include router in the FastAPI app
        app.include_router(router)
        
        # Store registration metadata
        registration_map[controller_name] = {
            "router": router,
            "controller_class": controller_cls,
            "controller_instance": controller_instance,
            "prefix": prefix
        }
    
    return registration_map


def get_all_vulnerable_endpoints(
    module: Optional[Any] = None
) -> List[Dict[str, Any]]:
    """
    Discovers and returns metadata for all vulnerable LLM endpoints.
    
    This function inspects a module (or the current module by default) for
    classes decorated with @vulnerable_llm_controller and extracts all their
    vulnerability levels and attack vectors.
    
    Args:
        module: Module to inspect for controllers (defaults to caller's module)
        
    Returns:
        List of vulnerability endpoint metadata dictionaries
        
    Example:
        endpoints = get_all_vulnerable_endpoints()
        for endpoint in endpoints:
            print(f"Vulnerability: {endpoint['name']}")
            for level in endpoint['levels']:
                print(f"  Level: {level['level']}")
                for vector in level['attack_vectors']:
                    print(f"    Attack: {vector['description']}")
    """
    if module is None:
        # Get the module of the caller
        frame = inspect.currentframe()
        if frame and frame.f_back:
            module_name = frame.f_back.f_globals.get("__name__")
            if isinstance(module_name, str):
                module = sys.modules.get(module_name)
    
    return get_vulnerable_controller_metadata()


def get_vulnerable_controller_metadata(controllers: Optional[List[Type]] = None) -> List[Dict[str, Any]]:
    """Return decorator-derived metadata for decorated controller classes."""
    endpoints = []

    for registration in _get_controller_registrations(controllers):
        endpoints.append({
            "name": registration.name,
            "description_label": registration.description,
            "levels": [_endpoint_to_dict(endpoint) for endpoint in registration.endpoints],
            "router": getattr(registration.cls, "_vulnerable_llm_metadata", {}).get("router"),
            "controller_class": registration.cls,
        })

    return endpoints


def get_facade_vulnerability_definitions(controllers: Optional[List[Type]] = None) -> List[Dict[str, Any]]:
    """Build facade vulnerability definitions from decorator metadata."""
    controller_metadata = get_vulnerable_controller_metadata(controllers)
    definitions = []

    for endpoint in controller_metadata:
        controller_name = str(endpoint.get("name", ""))
        display_name = "".join(part.capitalize() for part in controller_name.split("_"))
        template_base = "indirect_prompt_injection_template" if controller_name == "indirect_prompt_injection" else "prompt_injection_template"
        resource_information = {
            "htmlResource": {
                "resourceType": "HTML",
                "isAbsolute": False,
                "uri": f"{APP_BASE_PATH}/static/facade/{template_base}.html",
            },
            "staticResources": [
                {
                    "resourceType": "CSS",
                    "isAbsolute": False,
                    "uri": f"{APP_BASE_PATH}/static/facade/{template_base}.css",
                },
                {
                    "resourceType": "JAVASCRIPT",
                    "isAbsolute": False,
                    "uri": f"{APP_BASE_PATH}/static/facade/{template_base}.js",
                },
            ],
        }

        levels = []
        for level in endpoint.get("levels", []):
            levels.append({
                "levelIdentifier": level.get("level", "unknown"),
                "variant": getattr(level.get("variant"), "value", level.get("variant", "UNSECURE")),
                "hints": [],
                "resourceInformation": resource_information,
            })

        definitions.append({
            "name": display_name,
            "id": display_name,
            "description": endpoint.get("description_label", ""),
            "vulnerabilityTypes": [],
            "levels": levels,
        })

    return definitions


def get_vulnerability_summary(module: Optional[Any] = None) -> Dict[str, Any]:
    """
    Generates a summary of all vulnerabilities and their levels.
    
    Args:
        module: Module to inspect (defaults to caller's module)
        
    Returns:
        Dictionary summarizing all vulnerabilities, levels, and attack vectors
        
    Example:
        summary = get_vulnerability_summary()
        # {
        #   "total_vulnerabilities": 2,
        #   "total_levels": 8,
        #   "vulnerabilities": [
        #     {
        #       "name": "prompt_injection",
        #       "levels": 2,
        #       "attack_vectors": 4
        #     }
        #   ]
        # }
    """
    endpoints = get_all_vulnerable_endpoints(module)
    
    vulnerability_list = []
    total_levels = 0
    total_vectors = 0
    
    for endpoint in endpoints:
        levels = endpoint.get("levels", [])
        level_count = len(levels)
        
        vector_count = 0
        for level in levels:
            vector_count += len(level.get("attack_vectors", []))
        
        vulnerability_list.append({
            "name": endpoint.get("name"),
            "description": endpoint.get("description_label"),
            "levels": level_count,
            "attack_vectors": vector_count
        })
        
        total_levels += level_count
        total_vectors += vector_count
    
    return {
        "total_vulnerabilities": len(vulnerability_list),
        "total_levels": total_levels,
        "total_attack_vectors": total_vectors,
        "vulnerabilities": vulnerability_list
    }
