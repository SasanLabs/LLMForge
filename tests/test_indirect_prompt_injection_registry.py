import pytest

import src.controllers.indirect_prompt_injection_controller  # noqa: F401
from src.framework.decorators import Variant, VulnerabilityType, get_registry
from src.framework.properties_loader import PropertiesLoader


def _controller():
    return next(c for c in get_registry() if c.name == "indirect_prompt_injection")


def _endpoint(level: str):
    return next(e for e in _controller().endpoints if e.level == level)


@pytest.mark.parametrize(
    "level,expected_descriptions,expected_payloads,expected_exposure",
    [
        (
            "level_1",
            [
                "attack.indirect_obfuscated_key_request",
                "attack.indirect_source_instruction",
            ],
            [
                "payload.indirect_obfuscated_api_key",
                "payload.indirect_source_instruction",
            ],
            [
                [VulnerabilityType.INDIRECT_PROMPT_INJECTION],
                [VulnerabilityType.INDIRECT_PROMPT_INJECTION],
            ],
        ),
        (
            "level_2",
            ["attack.indirect_hidden_comment"],
            ["payload.indirect_hidden_comment"],
            [[VulnerabilityType.INDIRECT_PROMPT_INJECTION]],
        ),
        (
            "level_3",
            ["attack.indirect_multisource_confusion"],
            ["payload.indirect_multisource_confusion"],
            [[VulnerabilityType.INDIRECT_PROMPT_INJECTION]],
        ),
        (
            "level_4",
            ["attack.indirect_hardened"],
            ["payload.indirect_na"],
            [[]],
        ),
    ],
)
def test_indirect_attack_vectors_use_indirect_specific_keys(
    level, expected_descriptions, expected_payloads, expected_exposure
):
    endpoint = _endpoint(level)
    assert [av.description for av in endpoint.attack_vectors] == expected_descriptions
    assert [av.payload for av in endpoint.attack_vectors] == expected_payloads
    assert [av.vulnerability_exposed for av in endpoint.attack_vectors] == expected_exposure


def test_indirect_payload_locale_keys_resolve_to_real_text():
    PropertiesLoader.clear_cache()
    required_keys = [
        "attack.indirect_source_instruction",
        "attack.indirect_obfuscated_key_request",
        "attack.indirect_hidden_comment",
        "attack.indirect_multisource_confusion",
        "attack.indirect_hardened",
        "payload.indirect_source_instruction",
        "payload.indirect_obfuscated_api_key",
        "payload.indirect_hidden_comment",
        "payload.indirect_multisource_confusion",
        "payload.indirect_na",
    ]
    for key in required_keys:
        value = PropertiesLoader.get_property(key)
        assert value != key, f"locale key unresolved: {key}"
        assert value.strip(), f"locale value empty: {key}"


def test_level4_endpoint_registered_as_secure():
    endpoint = _endpoint("level_4")
    assert endpoint.variant is Variant.SECURE
    assert endpoint.secret_token is None
