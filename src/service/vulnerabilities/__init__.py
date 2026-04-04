"""Vulnerability labs for LLMForge."""

from .prompt_injection_lab import (
    LEVELS,
    evaluate_level,
    verify_level_secret,
)

from .indirect_prompt_injection_lab import (
    INDIRECT_LEVELS,
    evaluate_indirect_level,
    verify_indirect_level_secret,
)

__all__ = [
    "LEVELS",
    "evaluate_level",
    "verify_level_secret",
    "INDIRECT_LEVELS",
    "evaluate_indirect_level",
    "verify_indirect_level_secret",
]
