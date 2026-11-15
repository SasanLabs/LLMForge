"""
Cross-Tenant AI Memory Leakage Controller

A shared AI customer-support assistant whose conversation memory is not isolated per
customer. Maps to OWASP LLM02:2026 Sensitive Information Disclosure.
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
from ..service.vulnerabilities import evaluate_cross_tenant_memory_level
from ..service.vulnerabilities.cross_tenant_memory_lab import DEFAULT_TENANT_ID


@vulnerable_llm_controller(
    name="cross_tenant_memory_leakage",
    description=(
        "<p>Cross-Tenant AI Memory Leakage maps to OWASP LLM02:2026 Sensitive Information "
        "Disclosure. A SaaS vendor serves one AI support assistant to several enterprise "
        "customers and lets it remember earlier conversations. When the application puts "
        "memories owned by other customers into the model's context, it is relying on the "
        "model to decide what it may reveal &mdash; which is not a security boundary.</p>"
        "<p>You are signed in as a BluePeak Logistics user. Every response reports, "
        "separately, whether another customer's memory reached the model (context "
        "contamination) and whether the answer actually contained that customer's data "
        "(disclosure).</p>"
        "<p>References:</p><ul>"
        "<li><a href='https://genai.owasp.org/llmrisk/llm022025-sensitive-information-disclosure/' target='_blank' rel='noopener'>OWASP LLM02 Sensitive Information Disclosure</a></li>"
        "</ul>"
    ),
)
class CrossTenantMemoryLeakageController:
    """Cross-Tenant AI Memory Leakage vulnerability levels."""

    async def _handle_level(self, level: int, request: Request) -> dict:
        try:
            data = await request.json()
            if not isinstance(data, dict):
                return {"error": "Request body must be a JSON object"}
            user_input = str(data.get("user_input", ""))
            # Stands in for the tenant a real session/auth layer would resolve.
            tenant_id = str(data.get("tenant_id") or DEFAULT_TENANT_ID)
            model = data.get("model")
            return await evaluate_cross_tenant_memory_level(
                level, user_input, tenant_id=tenant_id, model=model)
        except ValueError as exc:
            return {"error": str(exc)}
        except httpx.HTTPError:
            return {"error": "Model service unavailable"}

    @vulnerable_llm_endpoint(
        level="level_1",
        variant=Variant.UNSECURE,
        html_template="cross_tenant_memory_template",
        method="POST",
    )
    @attack_vector(
        vulnerability_exposed=[VulnerabilityType.CROSS_TENANT_MEMORY_LEAKAGE],
        description="attack.cross_tenant_memory_unfiltered",
        payload="payload.cross_tenant_memory_l1_hint_nudge",
    )
    @attack_vector(
        vulnerability_exposed=[VulnerabilityType.CROSS_TENANT_MEMORY_LEAKAGE],
        description="attack.cross_tenant_memory_unfiltered",
        payload="payload.cross_tenant_memory_l1_summary_request",
    )
    async def level1(self, request: Request) -> dict:
        """Level 1: Unfiltered shared memory"""
        return await self._handle_level(1, request)

    @vulnerable_llm_endpoint(
        level="level_2",
        variant=Variant.UNSECURE,
        html_template="cross_tenant_memory_template",
        method="POST",
    )
    @attack_vector(
        vulnerability_exposed=[VulnerabilityType.CROSS_TENANT_MEMORY_LEAKAGE],
        description="attack.cross_tenant_memory_model_directed",
        payload="payload.cross_tenant_memory_l2_hint_nudge",
    )
    @attack_vector(
        vulnerability_exposed=[VulnerabilityType.CROSS_TENANT_MEMORY_LEAKAGE],
        description="attack.cross_tenant_memory_model_directed",
        payload="payload.cross_tenant_memory_l2_incident_request",
    )
    async def level2(self, request: Request) -> dict:
        """Level 2: Model-directed memory retrieval"""
        return await self._handle_level(2, request)

    @vulnerable_llm_endpoint(
        level="level_3",
        variant=Variant.SECURE,
        html_template="cross_tenant_memory_template",
        method="POST",
    )
    @attack_vector(
        vulnerability_exposed=[VulnerabilityType.CROSS_TENANT_MEMORY_LEAKAGE],
        description="attack.cross_tenant_memory_tenant_isolated",
        payload="payload.cross_tenant_memory_l3_na",
    )
    async def level3(self, request: Request) -> dict:
        """Level 3: Tenant-isolated memory"""
        return await self._handle_level(3, request)
