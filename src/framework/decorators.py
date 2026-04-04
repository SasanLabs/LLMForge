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
    methods: str = "GET",
    secret_token: Optional[str] = None,
    html_template_key: Optional[str] = None,
    locale: str = "us"
) -> Callable:
    """
    Marks a function as a vulnerability level endpoint.
    
    This decorator attaches metadata about the security level, variant type,
    and HTTP methods supported by this endpoint.
    
    Args:
        level: Level identifier (e.g., "LEVEL_1", "LEVEL_2")
        variant: UNSECURE or SECURE implementation variant
        html_template: Name of HTML template for UI rendering
        methods: HTTP method supported as string (e.g., "GET" or "POST")
        secret_token: Optional secret token for this level (for verification)
        html_template_key: Optional properties file key to load template name from
        locale: Locale code for properties file (default: "us")
        
    Returns:
        Decorator function
        
    Example:
        @vulnerable_llm_endpoint(
            level="LEVEL_1",
            variant=Variant.UNSECURE,
            html_template="level1",
            methods="POST",
            secret_token="secret_key_123"
        )
        async def level1(self, request: Request):
            ...
    """
    if not isinstance(methods, str):
        raise ValueError("methods must be a single HTTP method as string (e.g., 'GET' or 'POST')")
    
    methods = methods.upper()
    if methods not in ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"]:
        raise ValueError(f"Invalid HTTP method: {methods}")
    
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
            "methods": [methods],  # Store as list for compatibility with registry
            "secret_token": secret_token,
            "attack_vectors": []
        })
        
        return func
    return decorator


def attack_vector(
    vulnerability_exposed: List[str],
    description_key: str,
    payload_key: str = "payload.na",
    locale: str = "us"
) -> Callable:
    """
    Adds attack vector metadata to a vulnerable endpoint.
    
    This decorator augments an endpoint with information about specific
    attack vectors, payloads, and vulnerability types that can be tested.
    
    Payload and description are loaded from properties files to support
    multiple formats (plain text, HTML, multi-line, etc.).
    
    Args:
        vulnerability_exposed: List of vulnerability types exposed
        description_key: Properties file key to load description from
        payload_key: Properties file key to load payload from (default: "payload.na")
        locale: Locale code for properties file (default: "us")
        
    Returns:
        Decorator function
        
    Example:
        @attack_vector(
            vulnerability_exposed=["Prompt Injection"],
            description_key="attack.direct_injection",
            payload_key="attack.direct_injection.payload"
        )
        async def level1(self, request: Request):
            ...
    """
    def decorator(func: Callable) -> Callable:
        if not hasattr(func, "_vulnerable_llm_levels"):
            func._vulnerable_llm_levels = []
        
        # Load from properties
        try:
            desc = PropertiesLoader.get_property(description_key, locale)
        except FileNotFoundError:
            desc = f"[Key not found: {description_key}]"
        
        try:
            pay = PropertiesLoader.get_property(payload_key, locale)
        except FileNotFoundError:
            pay = "[Key not found: payload]"
        
        # Add attack vector to all levels associated with this function
        for level in func._vulnerable_llm_levels:
            level["attack_vectors"].append({
                "vulnerability_exposed": vulnerability_exposed,
                "payload": pay,
                "description": desc,
                "description_key": description_key,
                "payload_key": payload_key
            })
        
        return func
    return decorator
