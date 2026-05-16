"""
LLM Orchestrated BOLA Controller - Framework Version

Uses the decorator-driven framework to define BOLA (Broken Object Level Access) vulnerability levels.
Demonstrates how an LLM-powered chatbot can be exploited with malicious prompts to access other users' data.
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
from ..service.vulnerabilities.bola_chatbot_lab import evaluate_level


@vulnerable_llm_controller(
    name="bola_chatbot",
    description=(
        "Broken Object Level Authorization (BOLA) is the #1 vulnerability in the OWASP API "
        "Security Top 10. It occurs when an API grants access to data objects without "
        "verifying that the requesting user actually owns or has permission to view them — "
        "authorization is enforced at the endpoint level but not at the individual object level. "
        "In LLM-powered systems this takes a new and dangerous form: when access control logic "
        "is delegated to the model through prompt instructions, an attacker can manipulate the "
        "LLM into retrieving another user's records simply by asking — bypassing restrictions "
        "that were never enforced in code. The model becomes the vulnerability. "
        "\n\n"
        "References:\n"
        "- OWASP API1:2023 Broken Object Level Authorization: https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/\n"
        "- OWASP Web Security Testing Guide — API BOLA: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/12-API_Testing/02-API_Broken_Object_Level_Authorization"
    ),
)
class BOLAChatbotController:
    """LLM Orchestrated BOLA vulnerability levels - Medical Chatbot."""

    @vulnerable_llm_endpoint(
        level="level_1",
        variant=Variant.UNSECURE,
        html_template="bola/bola_chatbot_level1",
        method="POST"
    )
    @attack_vector(
        vulnerability_exposed=[VulnerabilityType.BOLA],
        description="attack.direct_patient_id_request",
        payload="payload.l1_direct_request"
    )
    @attack_vector(
        vulnerability_exposed=[VulnerabilityType.BOLA],
        description="attack.patient_id_injection",
        payload="payload.l1_id_injection"
    )
    async def level1(self, request: Request) -> dict:
        """Level 1: No Access Controls - LLM can freely choose any patient ID"""
        data = await request.json()
        user_input = data.get("user_input", "")
        model = data.get("model")
        
        try:
            # In Level 1, LLM orchestrates which patient to access
            # current_patient_id is just a placeholder, LLM can override it
            return await evaluate_level(
                1,
                user_input,
                current_patient_id="patient_001",
                model=model
            )
        except ValueError as exc:
            return {"error": str(exc)}
        except httpx.RequestError as exc:
            return {"error": "Model service unavailable"}

    @vulnerable_llm_endpoint(
        level="level_2",
        variant=Variant.UNSECURE,
        html_template="bola/bola_chatbot_level2",
        method="POST"
    )
    @attack_vector(
        vulnerability_exposed=[VulnerabilityType.BOLA],
        description="attack.prompt_injection_bypass",
        payload="payload.l2_prompt_injection"
    )
    @attack_vector(
        vulnerability_exposed=[VulnerabilityType.BOLA],
        description="attack.context_confusion",
        payload="payload.l2_context_confusion"
    )
    async def level2(self, request: Request) -> dict:
        """Level 2: Prompt-Level Guard Rails - System prompt restricts to current patient but bypassable"""
        data = await request.json()
        user_input = data.get("user_input", "")
        model = data.get("model")
        
        try:
            # Level 2: Current patient is specified in system prompt but LLM can override via prompt injection
            return await evaluate_level(
                2,
                user_input,
                current_patient_id="patient_001",
                model=model
            )
        except ValueError as exc:
            return {"error": str(exc)}
        except httpx.RequestError as exc:
            return {"error": "Model service unavailable"}

    @vulnerable_llm_endpoint(
        level="level_3",
        variant=Variant.SECURE,
        html_template="bola/bola_chatbot_level3",
        method="POST"
    )
    @attack_vector(
        vulnerability_exposed=[VulnerabilityType.BOLA],
        description="attack.application_layer_protected",
        payload="payload.l3_application_controls"
    )
    async def level3(self, request: Request) -> dict:
        """Level 3: Application-Layer Guard Rails - Backend enforces patient ID"""
        data = await request.json()
        user_input = data.get("user_input", "")
        model = data.get("model")
        
        try:
            # Level 3: Patient ID is hardcoded by backend (like from authentication/session cookie)
            # LLM cannot override this - it comes from backend authorization layer
            # In a real implementation, this would come from request.user.patient_id or session cookie
            authenticated_patient_id = "patient_001"  # Hardcoded here since no auth system shown
            
            return await evaluate_level(
                3,
                user_input,
                current_patient_id=authenticated_patient_id,
                model=model
            )
        except ValueError as exc:
            return {"error": str(exc)}
        except httpx.RequestError as exc:
            return {"error": "Model service unavailable"}
