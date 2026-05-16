"""
RAG Context Poisoning Controller

Simulates AI coding assistant vulnerability where retrieved context can be poisoned.
"""

from fastapi import Request
import httpx

from ..framework import (
    vulnerable_llm_controller,
    vulnerable_llm_endpoint,
    attack_vector,
    Variant,
    VulnerabilityType,
)
from ..service.vulnerabilities import RAG_LEVELS, evaluate_rag_level, validate_rag_challenge


@vulnerable_llm_controller(
    name="rag-context-poisoning",
    description="RAG Context Poisoning Vulnerability",
)
class RagContextPoisoningController:
    """RAG Context Poisoning vulnerability levels."""

    async def _handle_level(self, level: int, request: Request) -> dict:
        data = await request.json()
        action = str(data.get("action", "generate")).strip().lower()

        if action == "validate":
            session_id = str(data.get("challenge_session_id", "")).strip()
            selected_doc_ids = data.get("selected_doc_ids", [])
            return validate_rag_challenge(level, session_id, selected_doc_ids)

        user_input = data.get("user_input", "")
        model = data.get("model")

        try:
            return await evaluate_rag_level(level, user_input, model=model)
        except ValueError as exc:
            return {"error": str(exc)}
        except httpx.RequestError:
            return {"error": "Model service unavailable"}

    @vulnerable_llm_endpoint(
        level="level_1",
        variant=Variant.UNSECURE,
        html_template="rag_poisoning_template",
        method="POST",
        secret_token="rag_l1_T3mP0iS0n"
    )
    @attack_vector(
        vulnerability_exposed=[VulnerabilityType.RAG_CONTEXT_POISONING],
        description="attack.obvious_poisoned_guidance",
        payload="payload.l1_code_request"
    )
    async def level1(self, request: Request) -> dict:
        """Level 1: Obvious Poisoned Guidance"""
        return await self._handle_level(1, request)

    @vulnerable_llm_endpoint(
        level="level_2",
        variant=Variant.UNSECURE,
        html_template="rag_poisoning_template",
        method="POST",
        secret_token="rag_l2_H1dD3nP0iS0n"
    )
    @attack_vector(
        vulnerability_exposed=[VulnerabilityType.RAG_CONTEXT_POISONING],
        description="attack.hidden_instruction_injection",
        payload="payload.l2_code_request"
    )
    async def level2(self, request: Request) -> dict:
        """Level 2: Hidden Instruction Injection"""
        return await self._handle_level(2, request)

    @vulnerable_llm_endpoint(
        level="level_3",
        variant=Variant.UNSECURE,
        html_template="rag_poisoning_template",
        method="POST",
        secret_token="rag_l3_MuLt1P0iS0n"
    )
    @attack_vector(
        vulnerability_exposed=[VulnerabilityType.RAG_CONTEXT_POISONING],
        description="attack.multi_document_poisoning",
        payload="payload.l3_code_request"
    )
    async def level3(self, request: Request) -> dict:
        """Level 3: Multi-Document Context Poisoning"""
        return await self._handle_level(3, request)