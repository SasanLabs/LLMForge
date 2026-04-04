"""
Prompt Injection Controller - Framework Version

Uses the decorator-driven framework to define prompt injection vulnerability levels.
"""

from fastapi import Request
import httpx

from ..framework import (
    vulnerable_llm_controller,
    vulnerable_llm_endpoint,
    attack_vector,
    Variant,
)
from ..service.vulnerabilities import LEVELS, evaluate_level



@vulnerable_llm_controller(
    name="prompt_injection",
    description_label="Prompt Injection Vulnerability"
)
class PromptInjectionController:
    """Prompt Injection vulnerability levels."""

    @vulnerable_llm_endpoint(
        level="level_1",
        variant=Variant.UNSECURE,
        html_template="prompt_injection_level1",
        methods="POST",
        secret_token="pi_l1_C9vT2mQ7xL4rN8kD"
    )
    @attack_vector(
        vulnerability_exposed=["Prompt Injection"],
        description_key="attack.direct_injection",
        payload_key="payload.direct_injection"
    )
    async def level1(self, request: Request) -> dict:
        """Level 1: No Guardrails"""
        data = await request.json()
        user_input = data.get("user_input", "")
        model = data.get("model")
        temperature = data.get("temperature")
        
        try:
            return await evaluate_level(1, user_input, secret_token="pi_l1_C9vT2mQ7xL4rN8kD", temperature=temperature, model=model)
        except ValueError as exc:
            return {"error": str(exc)}
        except httpx.RequestError as exc:
            return {"error": "Model service unavailable"}

    @vulnerable_llm_endpoint(
        level="level_2",
        variant=Variant.UNSECURE,
        html_template="prompt_injection_level2",
        methods="POST",
        secret_token="pi_l2_R5nW8zK1uP3aX6hM"
    )
    @attack_vector(
        vulnerability_exposed=["Prompt Injection"],
        description_key="attack.template_injection",
        payload_key="payload.template_injection"
    )
    async def level2(self, request: Request) -> dict:
        """Level 2: LLM Filter Exact Match"""
        data = await request.json()
        user_input = data.get("user_input", "")
        model = data.get("model")
        temperature = data.get("temperature")
        
        try:
            return await evaluate_level(2, user_input, secret_token="pi_l2_R5nW8zK1uP3aX6hM", temperature=temperature, model=model)
        except ValueError as exc:
            return {"error": str(exc)}
        except httpx.RequestError as exc:
            return {"error": "Model service unavailable"}

    @vulnerable_llm_endpoint(
        level="level_3",
        variant=Variant.UNSECURE,
        html_template="prompt_injection_level3",
        methods="POST",
        secret_token="pi_l3_J4qN7sV2yB9tD6pL"
    )
    @attack_vector(
        vulnerability_exposed=["Prompt Injection"],
        description_key="attack.context_confusion",
        payload_key="payload.context_confusion"
    )
    async def level3(self, request: Request) -> dict:
        """Level 3: Dual Filter Exact Match"""
        data = await request.json()
        user_input = data.get("user_input", "")
        model = data.get("model")
        temperature = data.get("temperature")
        
        try:
            return await evaluate_level(3, user_input, secret_token="pi_l3_J4qN7sV2yB9tD6pL", temperature=temperature, model=model)
        except ValueError as exc:
            return {"error": str(exc)}
        except httpx.RequestError as exc:
            return {"error": "Model service unavailable"}

    @vulnerable_llm_endpoint(
        level="level_4",
        variant=Variant.UNSECURE,
        html_template="prompt_injection_level4",
        methods="POST",
        secret_token="pi_l4_M8xP3dR6kT1vQ9nS"
    )
    @attack_vector(
        vulnerability_exposed=["Prompt Injection"],
        description_key="attack.hidden_content",
        payload_key="payload.hidden_content"
    )
    async def level4(self, request: Request) -> dict:
        """Level 4: Dual Filter with Exact Phrase"""
        data = await request.json()
        user_input = data.get("user_input", "")
        model = data.get("model")
        temperature = data.get("temperature")
        
        try:
            return await evaluate_level(4, user_input, secret_token="pi_l4_M8xP3dR6kT1vQ9nS", temperature=temperature, model=model)
        except ValueError as exc:
            return {"error": str(exc)}
        except httpx.RequestError as exc:
            return {"error": "Model service unavailable"}

    @vulnerable_llm_endpoint(
        level="level_5",
        variant=Variant.UNSECURE,
        html_template="prompt_injection_level5",
        methods="POST",
        secret_token="pi_l5_T2kV9mC4qH7xR1dN"
    )
    @attack_vector(
        vulnerability_exposed=["Prompt Injection"],
        description_key="attack.capability_disclosure",
        payload_key="payload.capability_disclosure"
    )
    async def level5(self, request: Request) -> dict:
        """Level 5: Dual Filter Normalized Match"""
        data = await request.json()
        user_input = data.get("user_input", "")
        model = data.get("model")
        temperature = data.get("temperature")
        
        try:
            return await evaluate_level(5, user_input, secret_token="pi_l5_T2kV9mC4qH7xR1dN", temperature=temperature, model=model)
        except ValueError as exc:
            return {"error": str(exc)}
        except httpx.RequestError as exc:
            return {"error": "Model service unavailable"}

    @vulnerable_llm_endpoint(
        level="level_6",
        variant=Variant.UNSECURE,
        html_template="prompt_injection_level6",
        methods="POST",
        secret_token="pi_l6_P7rD1wN5zK8mQ3tV"
    )
    @attack_vector(
        vulnerability_exposed=["Prompt Injection", "Delimiter Confusion"],
        description_key="attack.delimiter_confusion",
        payload_key="payload.delimiter_confusion"
    )
    async def level6(self, request: Request) -> dict:
        """Level 6: Delimited Channel Mismatch"""
        data = await request.json()
        user_input = data.get("user_input", "")
        model = data.get("model")
        temperature = data.get("temperature")
        
        try:
            return await evaluate_level(6, user_input, secret_token="pi_l6_P7rD1wN5zK8mQ3tV", temperature=temperature, model=model)
        except ValueError as exc:
            return {"error": str(exc)}
        except httpx.RequestError as exc:
            return {"error": "Model service unavailable"}

    @vulnerable_llm_endpoint(
        level="level_7",
        variant=Variant.UNSECURE,
        html_template="prompt_injection_level7",
        methods="POST",
        secret_token="pi_l7_X3nT8qL6vR2mK9dP"
    )
    @attack_vector(
        vulnerability_exposed=["Prompt Injection", "JSON Injection"],
        description_key="attack.json_merge",
        payload_key="payload.json_merge"
    )
    async def level7(self, request: Request) -> dict:
        """Level 7: JSON Guard + Override Merge"""
        data = await request.json()
        user_input = data.get("user_input", "")
        model = data.get("model")
        temperature = data.get("temperature")
        
        try:
            return await evaluate_level(7, user_input, secret_token="pi_l7_X3nT8qL6vR2mK9dP", temperature=temperature, model=model)
        except ValueError as exc:
            return {"error": str(exc)}
        except httpx.RequestError as exc:
            return {"error": "Model service unavailable"}

    @vulnerable_llm_endpoint(
        level="level_8",
        variant=Variant.UNSECURE,
        html_template="prompt_injection_level8",
        methods="POST",
        secret_token="pi_l8_K4jV7mR2nS9xP1wQ"
    )
    @attack_vector(
        vulnerability_exposed=["Prompt Injection", "Approval Confusion"],
        description_key="attack.approval_marker",
        payload_key="payload.approval_marker"
    )
    async def level8(self, request: Request) -> dict:
        """Level 8: Prefix Check + Approval Confusion"""
        data = await request.json()
        user_input = data.get("user_input", "")
        model = data.get("model")
        temperature = data.get("temperature")
        
        try:
            return await evaluate_level(8, user_input, secret_token="pi_l8_V6mQ2rT9kD4xN7pW", temperature=temperature, model=model)
        except ValueError as exc:
            return {"error": str(exc)}
        except httpx.RequestError as exc:
            return {"error": "Model service unavailable"}

    @vulnerable_llm_endpoint(
        level="level_9",
        variant=Variant.UNSECURE,
        html_template="prompt_injection_level9",
        methods="POST",
        secret_token="pi_l9_Y6tD3bN1sK8vR4wP"
    )
    @attack_vector(
        vulnerability_exposed=["Prompt Injection", "Comment Injection"],
        description_key="attack.comment_smuggling",
        payload_key="payload.comment_smuggling"
    )
    async def level9(self, request: Request) -> dict:
        """Level 9: Comment Smuggling + Cascade"""
        data = await request.json()
        user_input = data.get("user_input", "")
        model = data.get("model")
        temperature = data.get("temperature")
        
        try:
            return await evaluate_level(9, user_input, secret_token="pi_l9_K3xR8nP5qT2mV6dL", temperature=temperature, model=model)
        except ValueError as exc:
            return {"error": str(exc)}
        except httpx.RequestError as exc:
            return {"error": "Model service unavailable"}

    @vulnerable_llm_endpoint(
        level="level_10",
        variant=Variant.SECURE,
        html_template="prompt_injection_level10",
        methods="POST",
        secret_token=None
    )
    @attack_vector(
        vulnerability_exposed=[],
        description_key="attack.hardened",
        payload_key="payload.na"
    )
    async def level10(self, request: Request) -> dict:
        """Level 10: Hardened Defense"""
        data = await request.json()
        user_input = data.get("user_input", "")
        model = data.get("model")
        temperature = data.get("temperature")
        
        try:
            return await evaluate_level(10, user_input, secret_token=None, temperature=temperature, model=model)
        except ValueError as exc:
            return {"error": str(exc)}
        except httpx.RequestError as exc:
            return {"error": "Model service unavailable"}
