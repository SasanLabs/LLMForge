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


def test_unsecure_levels_are_registered_as_unsecure_with_no_secret():
    for level in ("level_1", "level_2", "level_3", "level_4"):
        endpoint = _endpoint(level)
        assert endpoint.variant is Variant.UNSECURE
        assert endpoint.secret_token is None
        assert endpoint.method == "POST"


def test_level5_is_registered_as_secure_with_no_attack_vector_exposed():
    endpoint = _endpoint("level_5")
    assert endpoint.variant is Variant.SECURE
    assert endpoint.secret_token is None
    assert endpoint.method == "POST"
    for av in endpoint.attack_vectors:
        assert av.vulnerability_exposed == []


@pytest.mark.parametrize(
    "level,expected_payloads",
    [
        ("level_1", ["payload.unbounded_consumption_l1_hint_nudge",
                     "payload.unbounded_consumption_l1_unbounded_output"]),
        ("level_2", ["payload.unbounded_consumption_l2_hint_nudge",
                     "payload.unbounded_consumption_l2_unbounded_output"]),
        ("level_3", ["payload.unbounded_consumption_l3_hint_nudge",
                     "payload.unbounded_consumption_l3_concurrent_burst"]),
        ("level_4", ["payload.unbounded_consumption_l4_hint_nudge",
                     "payload.unbounded_consumption_l4_chain_tool_calls"]),
        ("level_5", ["payload.unbounded_consumption_l5_na"]),
    ],
)
def test_hint_tiers_end_with_real_payload_in_order(level, expected_payloads):
    assert [av.payload for av in _endpoint(level).attack_vectors] == expected_payloads


def test_every_unsecure_attack_vector_exposes_unbounded_consumption():
    # Level 5 (SECURE) is the one deliberate exception -- its own test above checks
    # its vector is empty, not that it exposes anything.
    for endpoint in _controller().endpoints:
        if endpoint.level == "level_5":
            continue
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


def test_level4_and_level5_endpoints_are_served_through_the_app(monkeypatch):
    from fastapi.testclient import TestClient

    from src.app import app
    from src.service.vulnerabilities import unbounded_consumption_lab as lab

    async def fake(messages, *, model, temperature, num_predict=None):
        return "A plain summary.", {"prompt_tokens": 40, "output_tokens": 10,
                                    "duration_ms": 5, "done_reason": "stop"}

    monkeypatch.setattr(lab, "chat_completion_with_messages_and_stats", fake)
    lab.reset_concurrency_trackers()
    client = TestClient(app)
    base = "/llmforge/api/v1/vulnerabilities/unbounded-consumption"

    four = client.post(f"{base}/level4", json={"user_input": "hello"}).json()
    assert four["metrics"]["iteration_budget"] == lab.LEVELS[4].iteration_budget
    assert four["metrics"]["iterations_used"] == 0
    assert four["bypassed"] is False

    five = client.post(f"{base}/level5", json={"user_input": "hello"}).json()
    assert five["metrics"]["iteration_hard_cap"] == lab.LEVELS[5].iteration_hard_cap
    assert five["bypassed"] is False


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


def test_locale_payload_number_stays_in_sync_with_the_iteration_budget():
    """Same drift risk as the l3 guard above, for Level 4's 'at least N' prose
    against iteration_budget. l5_na also quotes the number as "the same N" -- both
    are checked."""
    from src.service.vulnerabilities import unbounded_consumption_lab as lab

    text = (ROOT / "locale" / "messages_us.properties").read_text(encoding="utf-8")
    budget = str(lab.LEVELS[4].iteration_budget)

    l4_line = next(l for l in text.splitlines()
                  if l.startswith("payload.unbounded_consumption_l4_chain_tool_calls="))
    assert budget in l4_line, f"l4 payload doesn't mention iteration_budget ({budget}): {l4_line}"

    l5_line = next(l for l in text.splitlines()
                  if l.startswith("payload.unbounded_consumption_l5_na="))
    assert budget in l5_line, f"l5 payload doesn't mention iteration_budget ({budget}): {l5_line}"
