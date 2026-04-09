"""
LLMForge Decorator System

Provides decorators for marking classes and methods as vulnerable LLM controllers,
endpoints with security levels, and associated attack vectors.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Callable, List, Optional


# =========================
# Models
# =========================

class Variant(Enum):
    UNSECURE = "UNSECURE"
    SECURE = "SECURE"


@dataclass
class AttackVector:
    description: str
    payload: str
    vulnerability_exposed: List[str] = field(default_factory=list)


@dataclass
class Endpoint:
    level: str
    method: str
    variant: Variant
    attack_vectors: List[AttackVector] = field(default_factory=list)
    html_template: str = ""
    secret_token: Optional[str] = None
    handler_name: str = ""


@dataclass
class Controller:
    name: str
    description: str
    cls: type
    endpoints: List[Endpoint]


# =========================
# Registry
# =========================

REGISTRY: List[Controller] = []


def register_controller(name: str, description: str, cls: type, endpoints: List[Endpoint]) -> None:
    controller = Controller(name=name, description=description, cls=cls, endpoints=endpoints)

    for index, existing in enumerate(REGISTRY):
        if existing.cls is cls or existing.name == name:
            REGISTRY[index] = controller
            return

    REGISTRY.append(controller)


# =========================
# Method Decorators
# =========================


def attack_vector(
    description: str,
    payload: str,
    vulnerability_exposed: List[str],
) -> Callable:
    def decorator(func: Callable) -> Callable:
        vectors = getattr(func, "__attack_vectors__", [])
        vectors.append(
            AttackVector(
                description=description,
                payload=payload,
                vulnerability_exposed=vulnerability_exposed,
            )
        )
        setattr(func, "__attack_vectors__", vectors)
        return func

    return decorator


def vulnerable_llm_endpoint(
    level: str,
    method: str = "GET",
    variant: Variant = Variant.UNSECURE,
    html_template: str = "",
    secret_token: Optional[str] = None
) -> Callable:
    def decorator(func: Callable) -> Callable:
        setattr(func, "__endpoint__", {
            "level": level,
            "method": method.upper(),
            "variant": variant,
            "html_template": html_template,
            "secret_token": secret_token,
        })
        return func

    return decorator


# =========================
# Class Decorator
# =========================


def vulnerable_llm_controller(
    name: str,
    description: str
) -> Callable:
    def decorator(cls: type) -> type:
        endpoints: List[Endpoint] = []

        for attr_name, method in cls.__dict__.items():
            if hasattr(method, "__endpoint__"):
                ep_meta = method.__endpoint__
                vectors = getattr(method, "__attack_vectors__", [])

                endpoint = Endpoint(
                    level=ep_meta["level"],
                    method=ep_meta["method"],
                    variant=ep_meta["variant"],
                    html_template=ep_meta["html_template"],
                    secret_token=ep_meta["secret_token"],
                    attack_vectors=vectors,
                    handler_name=attr_name,
                )

                endpoints.append(endpoint)

        cls._vulnerable_llm_metadata = {
            "name": name,
            "description_label": description,
            "router": None,
            "levels": endpoints,
        }

        register_controller(name=name, description=description, cls=cls, endpoints=endpoints)
        return cls

    return decorator


# =========================
# Helpers
# =========================


def get_registry() -> List[Controller]:
    return REGISTRY


def get_registered_vulnerable_controllers() -> List[type]:
    return [controller.cls for controller in REGISTRY]
