"""
LLMForge Controller Registry and Auto-Discovery System

Provides automatic registration of vulnerable LLM controllers with FastAPI
and metadata discovery for scanners and UI components.
"""

import inspect
import sys
from typing import List, Dict, Any, Type, Optional
from fastapi import APIRouter
from .decorators import vulnerable_llm_controller


def register_controllers(
    app: Any,
    controllers: List[Type]
) -> Dict[str, Any]:
    """
    Automatically registers vulnerable LLM controllers with a FastAPI application.
    
    This function inspects controller classes for vulnerability level metadata
    and registers each level as a FastAPI route. The resulting URI structure is:
    /llmforge/<controller_name>/<level_name>
    
    Args:
        app: FastAPI application instance
        controllers: List of controller classes to register
        
    Returns:
        Dictionary mapping controller names to their registration metadata
        
    Example:
        app = FastAPI()
        register_controllers(app, [PromptInjectionController, DataExfilController])
        
        # Creates routes like:
        # GET/POST /llmforge/prompt_injection/level1
        # GET/POST /llmforge/prompt_injection/level2
        # GET/POST /llmforge/data_exfil/level1
    """
    registration_map = {}
    
    for controller_cls in controllers:
        # Verify the class has controller metadata
        meta = getattr(controller_cls, "_vulnerable_llm_metadata", None)
        if not meta:
            continue
        
        # Create router for this controller
        controller_name = meta["name"]
        prefix = f"/llmforge/{controller_name}"
        router = APIRouter(prefix=prefix)
        meta["router"] = router
        
        # Instantiate controller
        controller_instance = controller_cls()
        
        # Iterate through all methods and register level endpoints
        for method_name, method in inspect.getmembers(
            controller_instance, 
            predicate=inspect.ismethod
        ):
            levels = getattr(method, "_vulnerable_llm_levels", [])
            
            for level_meta in levels:
                path = f"/{level_meta['level']}"
                
                # Register for each HTTP method
                for http_method in level_meta.get("methods", ["GET"]):
                    router.add_api_route(
                        path, 
                        method, 
                        methods=[http_method]
                    )
        
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
            module = sys.modules.get(module_name)
    
    endpoints = []
    
    # Inspect all classes in the module
    if module:
        for name, obj in inspect.getmembers(module, inspect.isclass):
            meta = getattr(obj, "_vulnerable_llm_metadata", None)
            if not meta:
                continue
            
            levels = []
            
            # Extract levels from all methods in the controller
            for method_name, method in inspect.getmembers(obj, inspect.isfunction):
                method_levels = getattr(method, "_vulnerable_llm_levels", [])
                levels.extend(method_levels)
            
            # Create a copy of metadata with resolved levels
            endpoint_meta = {
                "name": meta.get("name"),
                "description_label": meta.get("description_label"),
                "levels": levels,
                "router": meta.get("router"),
                "controller_class": obj
            }
            endpoints.append(endpoint_meta)
    
    return endpoints


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
