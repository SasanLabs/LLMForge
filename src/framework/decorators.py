"""
LLMForge Decorator System

Provides decorators for marking classes and methods as vulnerable LLM controllers,
endpoints with security levels, and associated attack vectors.

Supports properties file integration for locale-specific text values.
"""

from enum import Enum
from typing import List, Optional, Callable, Any
from functools import wraps
from .properties_loader import PropertiesLoader


class Variant(Enum):
    """Enumeration for endpoint variants (secure vs unsecure implementations)."""
    UNSECURE = "UNSECURE"
    SECURE = "SECURE"


def vulnerable_llm_controller(
    name: str, 
    description_label: str,
    description_label_key: Optional[str] = None,
    locale: str = "us"
) -> Callable:
    """
    Marks a class as a vulnerable LLM controller.
    
    This decorator attaches metadata to a controller class that will be used
    for automatic registration with FastAPI and for UI/scanner discovery.
    
    Args:
        name: Controller name (used in URL paths like /llmforge/{name})
        description_label: Human-readable description of the vulnerability
        description_label_key: Optional properties file key to load description from
        locale: Locale code for properties file (default: "us")
        
    Returns:
        Decorator function
        
    Example:
        @vulnerable_llm_controller(
            name="prompt_injection", 
            description_label="Prompt Injection Vulnerability"
        )
        class PromptInjectionController:
            ...
            
        # Or with properties file:
        @vulnerable_llm_controller(
            name="prompt_injection", 
            description_label="vuln.prompt_injection",
            description_label_key="vuln.prompt_injection"
        )
        class PromptInjectionController:
            ...
    """
    def decorator(cls: type) -> type:
        # Load from properties if key is provided
        desc = description_label
        if description_label_key:
            try:
                desc = PropertiesLoader.get_property(
                    description_label_key, 
                    locale
                )
            except FileNotFoundError:
                # Fall back to provided description if properties file not found
                desc = description_label
        
        cls._vulnerable_llm_metadata = {
            "name": name,
            "description_label": desc,
            "router": None,  # Will be instantiated during registration
            "levels": []
        }
        return cls
    return decorator


def vulnerable_llm_endpoint(
    level: str,
    variant: Variant = Variant.UNSECURE,
    html_template: str = "",
    methods: List[str] = None,
    html_template_key: Optional[str] = None,
    locale: str = "us"
) -> Callable:
    """
    Marks a function as a vulnerability level endpoint.
    
    This decorator attaches metadata about the security level, variant type,
    and HTTP methods supported by this endpoint.
    
    Args:
        level: Level identifier (e.g., "level1", "level2")
        variant: UNSECURE or SECURE implementation variant
        html_template: Name of HTML template for UI rendering
        methods: List of HTTP methods supported (default: ["GET"])
        html_template_key: Optional properties file key to load template name from
        locale: Locale code for properties file (default: "us")
        
    Returns:
        Decorator function
        
    Example:
        @vulnerable_llm_endpoint(
            level="level1",
            variant=Variant.UNSECURE,
            html_template="level1",
            methods=["GET", "POST"]
        )
        async def level1(self, request: Request):
            ...
            
        # Or with properties file:
        @vulnerable_llm_endpoint(
            level="level1",
            variant=Variant.UNSECURE,
            html_template="level.unsecure_basic",
            html_template_key="level.unsecure_basic"
        )
        async def level1(self, request: Request):
            ...
    """
    if methods is None:
        methods = ["GET"]
    
    def decorator(func: Callable) -> Callable:
        if not hasattr(func, "_vulnerable_llm_levels"):
            func._vulnerable_llm_levels = []
        
        # Load from properties if key is provided
        template = html_template
        if html_template_key:
            try:
                template = PropertiesLoader.get_property(
                    html_template_key,
                    locale
                )
            except FileNotFoundError:
                # Fall back to provided template if properties file not found
                template = html_template
        
        func._vulnerable_llm_levels.append({
            "level": level,
            "variant": variant,
            "html_template": template,
            "methods": methods,
            "attack_vectors": []
        })
        
        return func
    return decorator


def attack_vector(
    vulnerability_exposed: List[str],
    payload: str = "NOT_APPLICABLE",
    description: str = "",
    description_key: Optional[str] = None,
    payload_key: Optional[str] = None,
    locale: str = "us"
) -> Callable:
    """
    Adds attack vector metadata to a vulnerable endpoint.
    
    This decorator augments an endpoint with information about specific
    attack vectors, payloads, and vulnerability types that can be tested.
    
    Args:
        vulnerability_exposed: List of vulnerability types exposed
        payload: Example payload for the attack (optional)
        description: Description of the attack vector
        description_key: Optional properties file key to load description from
        payload_key: Optional properties file key to load payload from
        locale: Locale code for properties file (default: "us")
        
    Returns:
        Decorator function
        
    Example:
        @attack_vector(
            vulnerability_exposed=["Prompt Injection"],
            payload="ignore previous instructions",
            description="Basic prompt injection attack"
        )
        async def level1(self, request: Request):
            ...
            
        # Or with properties file:
        @attack_vector(
            vulnerability_exposed=["Prompt Injection"],
            payload="attack.direct_injection.payload",
            payload_key="attack.direct_injection.payload",
            description="attack.direct_injection",
            description_key="attack.direct_injection"
        )
        async def level1(self, request: Request):
            ...
    """
    def decorator(func: Callable) -> Callable:
        if not hasattr(func, "_vulnerable_llm_levels"):
            func._vulnerable_llm_levels = []
        
        # Load from properties if keys are provided
        desc = description
        pay = payload
        
        if description_key:
            try:
                desc = PropertiesLoader.get_property(
                    description_key,
                    locale
                )
            except FileNotFoundError:
                # Fall back to provided description
                desc = description
        
        if payload_key:
            try:
                pay = PropertiesLoader.get_property(
                    payload_key,
                    locale
                )
            except FileNotFoundError:
                # Fall back to provided payload
                pay = payload
        
        # Add attack vector to all levels associated with this function
        for level in func._vulnerable_llm_levels:
            level["attack_vectors"].append({
                "vulnerability_exposed": vulnerability_exposed,
                "payload": pay,
                "description": desc
            })
        
        return func
    return decorator
