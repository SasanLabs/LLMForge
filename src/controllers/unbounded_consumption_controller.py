"""
Unbounded Consumption Controller

A summarization endpoint whose resource use is not bounded. Maps to OWASP LLM10:2025.
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
    UNBOUNDED_CONSUMPTION_LEVELS,
    evaluate_unbounded_consumption_level,
)


@vulnerable_llm_controller(
    name="unbounded_consumption",
    description=(
        "<p>Unbounded Consumption maps to OWASP LLM10:2025. The lab attacks availability and cost "
        "rather than data: a summarization endpoint that never limits how much a single request "
        "can consume lets one caller burn compute, money and queue capacity that everyone else "
        "shares.</p>"
        "<p>Every response reports the tokens the request billed. A level is bypassed when one "
        "request bills far more than a summary should.</p>"
        "<p>References:</p><ul>"
        "<li><a href='https://genai.owasp.org/llmrisk/llm102025-unbounded-consumption/' target='_blank' rel='noopener'>OWASP LLM10:2025 Unbounded Consumption</a></li>"
        "</ul>"
    ),
)
class UnboundedConsumptionController:
    """Unbounded Consumption vulnerability levels."""

    async def _handle_level(self, level: int, request: Request) -> dict:
        try:
            data = await request.json()
            if not isinstance(data, dict):
                return {"error": "Request body must be a JSON object"}
            user_input = str(data.get("user_input", ""))
            model = data.get("model")
            return await evaluate_unbounded_consumption_level(level, user_input, model=model)
        except ValueError as exc:
            return {"error": str(exc)}
        except httpx.HTTPError:
            return {"error": "Model service unavailable"}

    @vulnerable_llm_endpoint(
        level="level_1",
        variant=Variant.UNSECURE,
        html_template="unbounded_consumption_template",
        method="POST",
    )
    @attack_vector(
        vulnerability_exposed=[VulnerabilityType.UNBOUNDED_CONSUMPTION],
        description="attack.unbounded_consumption_no_limits",
        payload="payload.unbounded_consumption_l1_unbounded_output",
    )
    @attack_vector(
        vulnerability_exposed=[VulnerabilityType.UNBOUNDED_CONSUMPTION],
        description="attack.unbounded_consumption_no_limits",
        payload="payload.unbounded_consumption_l1_hint_nudge",
    )
    async def level1(self, request: Request) -> dict:
        """Level 1: No limits on input or output"""
        return await self._handle_level(1, request)

    @vulnerable_llm_endpoint(
        level="level_2",
        variant=Variant.UNSECURE,
        html_template="unbounded_consumption_template",
        method="POST",
    )
    @attack_vector(
        vulnerability_exposed=[VulnerabilityType.UNBOUNDED_CONSUMPTION],
        description="attack.unbounded_consumption_input_cap_only",
        payload="payload.unbounded_consumption_l2_unbounded_output",
    )
    @attack_vector(
        vulnerability_exposed=[VulnerabilityType.UNBOUNDED_CONSUMPTION],
        description="attack.unbounded_consumption_input_cap_only",
        payload="payload.unbounded_consumption_l2_hint_nudge",
    )
    async def level2(self, request: Request) -> dict:
        """Level 2: Input capped, output unbounded"""
        return await self._handle_level(2, request)

    @vulnerable_llm_endpoint(
        level="level_3",
        variant=Variant.UNSECURE,
        html_template="unbounded_consumption_template",
        method="POST",
    )
    @attack_vector(
        vulnerability_exposed=[VulnerabilityType.UNBOUNDED_CONSUMPTION],
        description="attack.unbounded_consumption_no_concurrency_control",
        payload="payload.unbounded_consumption_l3_concurrent_burst",
    )
    @attack_vector(
        vulnerability_exposed=[VulnerabilityType.UNBOUNDED_CONSUMPTION],
        description="attack.unbounded_consumption_no_concurrency_control",
        payload="payload.unbounded_consumption_l3_hint_nudge",
    )
    async def level3(self, request: Request) -> dict:
        """Level 3: Input and output capped, no concurrency control"""
        return await self._handle_level(3, request)
