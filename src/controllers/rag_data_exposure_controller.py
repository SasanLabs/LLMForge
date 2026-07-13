"""
RAG Sensitive Data Exposure Controller

Simulates sensitive data disclosure caused by unsafe RAG retrieval.
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
from ..service.vulnerabilities import (
    RAG_DATA_EXPOSURE_LEVELS,
    evaluate_rag_data_exposure_level,
    validate_rag_data_exposure_secret,
)


@vulnerable_llm_controller(
    name="rag_sensitive_data_exposure",
    description=(
        "<p>RAG Sensitive Data Exposure maps to OWASP LLM02:2025 Sensitive Information Disclosure. "
        "The lab demonstrates how retrieved context can place sensitive internal data directly into "
        "the model prompt, causing the assistant to reveal values that should never be exposed.</p>"
        "<p>It also prepares for OWASP LLM08:2025 Vector and Embedding Weaknesses by showing that "
        "FAISS returns similar vectors, while the application must enforce namespaces, metadata "
        "filters, and authorization decisions.</p>"
        "<p>References:</p><ul>"
        "<li><a href='https://genai.owasp.org/llmrisk/llm022025-sensitive-information-disclosure/' target='_blank' rel='noopener'>OWASP LLM02:2025 Sensitive Information Disclosure</a></li>"
        "<li><a href='https://genai.owasp.org/llmrisk/llm08-excessive-agency/' target='_blank' rel='noopener'>OWASP LLM08:2025 Vector and Embedding Weaknesses</a></li>"
        "</ul>"
    ),
)
class RagSensitiveDataExposureController:
    """RAG Sensitive Data Exposure vulnerability levels."""

    async def _handle_level(self, level: int, request: Request) -> dict:
        try:
            data = await request.json()
            if not isinstance(data, dict):
                return {"error": "Request body must be a JSON object"}
            action = str(data.get("action", "generate")).strip().lower()
            if action not in {"generate", "validate"}:
                return {"error": f"Unsupported action '{action}'"}

            if action == "validate":
                candidate_secret = str(data.get("candidate_secret", ""))
                return validate_rag_data_exposure_secret(level, candidate_secret)

            user_input = str(data.get("user_input", ""))
            model = data.get("model")
            return await evaluate_rag_data_exposure_level(level, user_input, model=model)
        except ValueError as exc:
            return {"error": str(exc)}
        except httpx.HTTPError:
            return {"error": "Model or embedding service unavailable"}

    @vulnerable_llm_endpoint(
        level="level_1",
        variant=Variant.UNSECURE,
        html_template="rag_data_exposure_template",
        method="POST",
    )
    @attack_vector(
        vulnerability_exposed=[VulnerabilityType.RAG_SENSITIVE_DATA_EXPOSURE],
        description="attack.rag_sensitive_direct_retrieval",
        payload="payload.rag_sensitive_l1_direct_query",
    )
    async def level1(self, request: Request) -> dict:
        """Level 1: Direct Sensitive Document Retrieval"""
        return await self._handle_level(1, request)

    @vulnerable_llm_endpoint(
        level="level_2",
        variant=Variant.UNSECURE,
        html_template="rag_data_exposure_template",
        method="POST",
    )
    @attack_vector(
        vulnerability_exposed=[VulnerabilityType.RAG_SENSITIVE_DATA_EXPOSURE],
        description="attack.rag_sensitive_semantic_bypass",
        payload="payload.rag_sensitive_l2_paraphrase",
    )
    async def level2(self, request: Request) -> dict:
        """Level 2: Keyword Denylist Bypassed by Semantic Retrieval"""
        return await self._handle_level(2, request)

    @vulnerable_llm_endpoint(
        level="level_3",
        variant=Variant.UNSECURE,
        html_template="rag_data_exposure_template",
        method="POST",
    )
    @attack_vector(
        vulnerability_exposed=[VulnerabilityType.RAG_SENSITIVE_DATA_EXPOSURE],
        description="attack.rag_sensitive_mistagged_low_doc",
        payload="payload.rag_sensitive_l3_low_doc_filter",
    )
    async def level3(self, request: Request) -> dict:
        """Level 3: Low-Sensitivity Metadata Filter Bypassed by Misclassified Chunk"""
        return await self._handle_level(3, request)

    @vulnerable_llm_endpoint(
        level="level_4",
        variant=Variant.SECURE,
        html_template="rag_data_exposure_template",
        method="POST",
    )
    @attack_vector(
        vulnerability_exposed=[],
        description="attack.rag_sensitive_hardened_chunk_scan",
        payload="payload.rag_sensitive_l4_na",
    )
    async def level4(self, request: Request) -> dict:
        """Level 4: Hardened - chunk-level sensitivity via ingest scan"""
        return await self._handle_level(4, request)

