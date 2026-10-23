from pathlib import Path

import pytest

import src.controllers.unbounded_consumption_controller  # noqa: F401  (registers the controller)
from src.framework.decorators import Variant, VulnerabilityType, get_registry

ROOT = Path(__file__).resolve().parents[1]


def _controller():
    return next(c for c in get_registry() if c.name == "unbounded_consumption")


def _endpoint(level: str):
    return next(e for e in _controller().endpoints if e.level == level)


def _locale_keys() -> set[str]:
    keys = set()
    for line in (ROOT / "locale" / "messages_us.properties").read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            keys.add(line.split("=", 1)[0])
    return keys


def test_all_levels_are_registered_as_unsecure_with_no_secret():
    for level in ("level_1", "level_2", "level_3"):
        endpoint = _endpoint(level)
        assert endpoint.variant is Variant.UNSECURE
        assert endpoint.secret_token is None
        assert endpoint.method == "POST"


@pytest.mark.parametrize(
    "level,expected_payloads",
    [
        ("level_1", ["payload.unbounded_consumption_l1_hint_nudge",
                     "payload.unbounded_consumption_l1_unbounded_output"]),
        ("level_2", ["payload.unbounded_consumption_l2_hint_nudge",
                     "payload.unbounded_consumption_l2_unbounded_output"]),
        ("level_3", ["payload.unbounded_consumption_l3_hint_nudge",
                     "payload.unbounded_consumption_l3_concurrent_burst"]),
    ],
)
def test_hint_tiers_end_with_real_payload_in_order(level, expected_payloads):
    assert [av.payload for av in _endpoint(level).attack_vectors] == expected_payloads


def test_every_attack_vector_exposes_unbounded_consumption():
    for endpoint in _controller().endpoints:
        for av in endpoint.attack_vectors:
            assert av.vulnerability_exposed == [VulnerabilityType.UNBOUNDED_CONSUMPTION]


def test_every_referenced_locale_key_exists():
    keys = _locale_keys()
    for endpoint in _controller().endpoints:
        for av in endpoint.attack_vectors:
            assert av.description in keys, av.description
            assert av.payload in keys, av.payload
    assert "vuln.unbounded_consumption" in keys


def test_facade_template_files_exist():
    for endpoint in _controller().endpoints:
        for ext in ("html", "css", "js"):
            assert (ROOT / "src" / "static" / "facade" / f"{endpoint.html_template}.{ext}").is_file()


def test_endpoints_are_served_through_the_app(monkeypatch):
    from fastapi.testclient import TestClient

    from src.app import app
    from src.service.vulnerabilities import unbounded_consumption_lab as lab

    async def fake(system_prompt, user_input, model, temperature, num_predict):
        return "summary", {"prompt_tokens": 100, "output_tokens": 600,
                           "duration_ms": 10, "done_reason": "stop"}

    monkeypatch.setattr(lab, "_call_llm", fake)
    lab.reset_concurrency_trackers()
    client = TestClient(app)
    base = "/llmforge/api/v1/vulnerabilities/unbounded-consumption"

    ok = client.post(f"{base}/level1", json={"user_input": "hello"}).json()
    assert ok["bypassed"] is True and ok["metrics"]["billed_tokens"] == 700

    blocked = client.post(f"{base}/level2", json={"user_input": "x" * 601}).json()
    assert blocked["input_accepted"] is False and blocked["reason"] == "max_input_chars"

    three = client.post(f"{base}/level3", json={"user_input": "hello"}).json()
    assert three["metrics"]["concurrency_budget"] == lab.LEVELS[3].concurrency_budget
    assert three["metrics"]["concurrent_requests"] == 1

    assert "error" in client.post(f"{base}/level1", json=["not", "an", "object"]).json()

    manifest = client.get("/llmforge/api/v1/vulnerabilities/unbounded-consumption").json()
    assert manifest


def test_locale_payload_number_stays_in_sync_with_the_concurrency_budget():
    """The l3 payload text names a request count in prose ("at least N requests").
    Properties files aren't templated at runtime here, so nothing enforces that N
    actually matches concurrency_budget -- this guard is what keeps them from
    silently drifting apart as either one is edited."""
    from src.service.vulnerabilities import unbounded_consumption_lab as lab

    text = (ROOT / "locale" / "messages_us.properties").read_text(encoding="utf-8")
    line = next(l for l in text.splitlines()
               if l.startswith("payload.unbounded_consumption_l3_concurrent_burst="))
    assert str(lab.LEVELS[3].concurrency_budget) in line, (
        f"locale text doesn't mention the current concurrency_budget "
        f"({lab.LEVELS[3].concurrency_budget}): {line}")
