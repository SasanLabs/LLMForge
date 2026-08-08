import src.controllers.indirect_prompt_injection_controller  # noqa: F401
from src.framework.decorators import Variant, get_registry
from src.framework.properties_loader import PropertiesLoader


def _endpoint(level: str):
    controller = next(
        item for item in get_registry() if item.name == "indirect_prompt_injection"
    )
    return next(endpoint for endpoint in controller.endpoints if endpoint.level == level)


def test_vulnerable_levels_expose_two_concrete_payloads_each():
    for level in ("level_1", "level_2", "level_3"):
        vectors = _endpoint(level).attack_vectors
        level_number = level.rsplit("_", 1)[1]
        assert len(vectors) == 2
        assert all(vector.vulnerability_exposed for vector in vectors)
        assert all(vector.payload.startswith(f"payload.indirect_l{level_number}") for vector in vectors)


def test_payloads_preserve_trusted_goal_and_cover_external_carriers():
    resolved = [
        PropertiesLoader.get_property(vector.payload)
        for level in ("level_1", "level_2", "level_3")
        for vector in _endpoint(level).attack_vectors
    ]

    assert len(resolved) == len(set(resolved))
    assert all("Trusted user goal:" in payload for payload in resolved)
    assert any("Retrieved webpage:" in payload for payload in resolved)
    assert any("Hidden HTML comment:" in payload for payload in resolved)
    assert any("External reference material:" in payload for payload in resolved)
    assert any("API_KEY" in payload for payload in resolved)
    assert any("DEPLOYMENT_SECRET" in payload for payload in resolved)
    assert any("DB_PASSWORD" in payload for payload in resolved)


def test_payload_and_description_keys_resolve_to_user_facing_text():
    for level in ("level_1", "level_2", "level_3", "level_4"):
        for vector in _endpoint(level).attack_vectors:
            assert PropertiesLoader.get_property(vector.payload) != vector.payload
            assert PropertiesLoader.get_property(vector.description) != vector.description


def test_hardened_level_remains_secure_and_has_no_exploit_payload():
    endpoint = _endpoint("level_4")
    assert endpoint.variant is Variant.SECURE
    assert endpoint.secret_token is None
    assert len(endpoint.attack_vectors) == 1
    assert endpoint.attack_vectors[0].vulnerability_exposed == []
    assert endpoint.attack_vectors[0].payload == "payload.indirect_l4_na"
