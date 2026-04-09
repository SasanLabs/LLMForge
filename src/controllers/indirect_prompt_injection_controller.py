"""
Indirect Prompt Injection Controller - Framework Version

Uses the decorator-driven framework to define indirect prompt injection vulnerability levels.
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
    evaluate_indirect_level,
)


@vulnerable_llm_controller(
    name="indirect_prompt_injection",
    description="Indirect Prompt Injection Attacks",
)
class IndirectPromptInjectionController:
    """Indirect Prompt Injection vulnerability levels."""

    @vulnerable_llm_endpoint(
        level="level_1",
        variant=Variant.UNSECURE,
        html_template="indirect_prompt_injection_level1",
        method="POST",
        secret_token="ind_l1_A9rQ2mX7tP4kV8"
    )
    @attack_vector(
        vulnerability_exposed=[VulnerabilityType.INDIRECT_PROMPT_INJECTION],
        description="attack.direct_injection",
        payload="payload.direct_injection"
    )
    async def level1(self, request: Request) -> dict:
        """Level 1: Basic Webpage Injection"""
        data = await request.json()
        user_input = data.get("user_input", "")
        source_type = data.get("source_type")
        source_value = data.get("source_value")
        temperature = data.get("temperature")
        model = data.get("model")
        
        try:
            return await evaluate_indirect_level(
                1,
                user_input,
                source_type=source_type,
                source_value=source_value,
                secret_token="ind_l1_A9rQ2mX7tP4kV8",
                temperature=temperature,
                is_secure=False,
                model=model
            )
        except ValueError as exc:
            return {"error": str(exc)}
        except httpx.RequestError as exc:
            return {"error": "Model service unavailable"}

    @vulnerable_llm_endpoint(
        level="level_2",
        variant=Variant.UNSECURE,
        html_template="indirect_prompt_injection_level2",
        method="POST",
        secret_token="ind_l2_N6wC3zR1yH8dF5"
    )
    @attack_vector(
        vulnerability_exposed=[VulnerabilityType.INDIRECT_PROMPT_INJECTION],
        description="attack.hidden_content",
        payload="payload.hidden_content"
    )
    async def level2(self, request: Request) -> dict:
        """Level 2: Hidden Injection (Stealth Attack)"""
        data = await request.json()
        user_input = data.get("user_input", "")
        source_type = data.get("source_type")
        source_value = data.get("source_value")
        temperature = data.get("temperature")
        model = data.get("model")
        
        try:
            return await evaluate_indirect_level(
                2,
                user_input,
                source_type=source_type,
                source_value=source_value,
                secret_token="ind_l2_N6wC3zR1yH8dF5",
                temperature=temperature,
                is_secure=False,
                model=model
            )
        except ValueError as exc:
            return {"error": str(exc)}
        except httpx.RequestError as exc:
            return {"error": "Model service unavailable"}

    @vulnerable_llm_endpoint(
        level="level_3",
        variant=Variant.UNSECURE,
        html_template="indirect_prompt_injection_level3",
        method="POST",
        secret_token="ind_l3_T4vM9qK2pS7xB1"
    )
    @attack_vector(
        vulnerability_exposed=[VulnerabilityType.INDIRECT_PROMPT_INJECTION],
        description="attack.context_confusion",
        payload="payload.context_confusion"
    )
    async def level3(self, request: Request) -> dict:
        """Level 3: Multi-Source Data Exfiltration"""
        data = await request.json()
        user_input = data.get("user_input", "")
        source_type = data.get("source_type")
        source_value = data.get("source_value")
        temperature = data.get("temperature")
        model = data.get("model")
        
        try:
            return await evaluate_indirect_level(
                3,
                user_input,
                source_type=source_type,
                source_value=source_value,
                secret_token="ind_l3_T4vM9qK2pS7xB1",
                temperature=temperature,
                is_secure=False,
                model=model
            )
        except ValueError as exc:
            return {"error": str(exc)}
        except httpx.RequestError as exc:
            return {"error": "Model service unavailable"}

    @vulnerable_llm_endpoint(
        level="level_4",
        variant=Variant.SECURE,
        html_template="indirect_prompt_injection_level4",
        method="POST",
        secret_token=None
    )
    @attack_vector(
        vulnerability_exposed=[],
        description="attack.hardened",
        payload="payload.na"
    )
    async def level4(self, request: Request) -> dict:
        """Level 4: Hardened Indirect Handling"""
        data = await request.json()
        user_input = data.get("user_input", "")
        source_type = data.get("source_type")
        source_value = data.get("source_value")
        temperature = data.get("temperature")
        model = data.get("model")
        
        try:
            return await evaluate_indirect_level(
                4,
                user_input,
                source_type=source_type,
                source_value=source_value,
                secret_token=None,
                temperature=temperature,
                is_secure=True,
                model=model
            )
        except ValueError as exc:
            return {"error": str(exc)}
        except httpx.RequestError as exc:
            return {"error": "Model service unavailable"}

