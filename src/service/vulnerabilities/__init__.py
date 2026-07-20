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

from .bola_chatbot_lab import (
    LEVELS as BOLA_LEVELS,
    evaluate_level as evaluate_bola_level,
    verify_level_secret as verify_bola_level_secret,
)

from .rag_poisoning_lab import (
    LEVELS as RAG_LEVELS,
    evaluate_level as evaluate_rag_level,
    validate_challenge as validate_rag_challenge,
)

from .rag_data_exposure_lab import (
    LEVELS as RAG_DATA_EXPOSURE_LEVELS,
    evaluate_level as evaluate_rag_data_exposure_level,
    validate_secret as validate_rag_data_exposure_secret,
)

__all__ = [
    "LEVELS",
    "evaluate_level",
    "verify_level_secret",
    "INDIRECT_LEVELS",
    "evaluate_indirect_level",
    "verify_indirect_level_secret",
    "BOLA_LEVELS",
    "evaluate_bola_level",
    "verify_bola_level_secret",
    "RAG_LEVELS",
    "evaluate_rag_level",
    "validate_rag_challenge",
    "RAG_DATA_EXPOSURE_LEVELS",
    "evaluate_rag_data_exposure_level",
    "validate_rag_data_exposure_secret",
]
