import pytest

import src.controllers.rag_data_exposure_controller  # noqa: F401  (registra o controller)
from src.framework.decorators import Variant, get_registry


def _endpoint(level: str):
    controller = next(
        c for c in get_registry() if c.name == "rag_sensitive_data_exposure"
    )
    return next(e for e in controller.endpoints if e.level == level)


def test_level4_endpoint_registered_as_secure():
    endpoint = _endpoint("level_4")
    assert endpoint.variant is Variant.SECURE
    assert endpoint.secret_token is None


@pytest.mark.parametrize(
    "level,expected_payloads",
    [
        (
            "level_1",
            [
                "payload.rag_sensitive_l1_hint_nudge",
                "payload.rag_sensitive_l1_direct_query",
            ],
        ),
        (
            "level_2",
            [
                "payload.rag_sensitive_l2_hint_nudge",
                "payload.rag_sensitive_l2_paraphrase",
            ],
        ),
        (
            "level_3",
            [
                "payload.rag_sensitive_l3_hint_nudge",
                "payload.rag_sensitive_l3_low_doc_filter",
            ],
        ),
        (
            "level_4",
            [
                "payload.rag_sensitive_l4_na",
            ],
        ),
    ],
)
def test_hint_tiers_end_with_real_payload_in_order(level, expected_payloads):
    endpoint = _endpoint(level)
    assert [av.payload for av in endpoint.attack_vectors] == expected_payloads
