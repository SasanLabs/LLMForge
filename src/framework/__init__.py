"""
LLMForge Framework

Python-based framework for testing and simulating LLM vulnerabilities
using a decorator-driven, metadata-centric architecture.

This package provides:
- Decorators for marking vulnerable controllers and endpoints
- Automatic FastAPI registration system
- Metadata discovery for scanners and UI components
- Properties file support for locale-specific text values
- Support for multiple vulnerability levels and attack vectors

Key components:
- Variant: Enum for endpoint variants (UNSECURE, SECURE)
- vulnerable_llm_controller: Decorator for controller classes
- vulnerable_llm_endpoint: Decorator for vulnerability level endpoints
- attack_vector: Decorator for attack vector metadata
- register_controllers: Automatic FastAPI registration
- get_all_vulnerable_endpoints: Metadata discovery interface
- PropertiesLoader: Locale-specific properties file loading
"""

from .decorators import (
    Variant,
    vulnerable_llm_controller,
    vulnerable_llm_endpoint,
    attack_vector,
)

from .registry import (
    register_controllers,
    get_all_vulnerable_endpoints,
    get_vulnerability_summary,
)

from .properties_loader import PropertiesLoader

__version__ = "1.0.0"
__author__ = "LLMForge Team"

__all__ = [
    # Enums
    "Variant",
    
    # Decorators
    "vulnerable_llm_controller",
    "vulnerable_llm_endpoint",
    "attack_vector",
    
    # Registry functions
    "register_controllers",
    "get_all_vulnerable_endpoints",
    "get_vulnerability_summary",
    
    # Properties
    "PropertiesLoader",
]
