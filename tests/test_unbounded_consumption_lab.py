import asyncio

import httpx
import pytest

from src import ollama_client
from src.service.vulnerabilities import unbounded_consumption_lab as lab


def _stub_llm(monkeypatch, *, prompt_tokens, output_tokens, done_reason="stop"):
    calls = []

    async def fake(system_prompt, user_input, model, temperature, num_predict):
        calls.append((system_prompt, user_input, model, temperature, num_predict))
        stats = {
            "prompt_tokens": prompt_tokens,
            "output_tokens": output_tokens,
            "duration_ms": 1234,
            "done_reason": done_reason,
        }
        return "generated text", stats

    monkeypatch.setattr(lab, "_call_llm", fake)
    return calls


def _run(level, text):
    return asyncio.run(lab.evaluate_level(level, text))


# --- input validation -------------------------------------------------------

def test_blank_input_is_blocked():
    result = lab._validate_input(lab.LEVELS[1], "   ")
    assert result.allowed is False
    assert result.reason == "empty_input"


def test_level1_accepts_input_far_larger_than_level2_allows():
    text = "x" * (lab.LEVELS[2].max_input_chars + 5_000)
    assert lab._validate_input(lab.LEVELS[1], text).allowed is True


def test_level2_blocks_input_over_its_cap():
    text = "x" * (lab.LEVELS[2].max_input_chars + 1)
    result = lab._validate_input(lab.LEVELS[2], text)
    assert result.allowed is False
    assert result.reason == "max_input_chars"


def test_level2_accepts_input_at_its_cap():
    text = "x" * lab.LEVELS[2].max_input_chars
    assert lab._validate_input(lab.LEVELS[2], text).allowed is True


def test_host_ceiling_applies_even_at_level1():
    result = lab._validate_input(lab.LEVELS[1], "x" * (lab.HOST_INPUT_CEILING_CHARS + 1))
    assert result.allowed is False
    assert result.reason == "host_input_ceiling"


def test_level3_caps_input_by_bytes_not_characters():
    cap = lab.LEVELS[3].max_input_bytes
    assert lab.LEVELS[3].max_input_chars is None  # bytes is the real cap here, not chars

    # Plain ASCII: chars == bytes, so the byte cap behaves just like a char cap would.
    ascii_at_cap = "x" * cap
    assert lab._validate_input(lab.LEVELS[3], ascii_at_cap).allowed is True
    assert lab._validate_input(lab.LEVELS[3], ascii_at_cap + "x").allowed is False

    # Multi-byte text: far fewer *characters* are needed to exceed the same byte cap,
    # which is exactly the point -- a character cap would have let this through.
    emoji = "😀" * (cap // 4 + 1)  # each is 4 UTF-8 bytes
    assert len(emoji) < cap  # well under a character-based cap of the same number
    assert len(emoji.encode("utf-8")) > cap  # but over the real, byte-based cap
    result = lab._validate_input(lab.LEVELS[3], emoji)
    assert result.allowed is False
    assert result.reason == "max_input_bytes"


def test_level3_budget_has_margin_over_the_measured_worst_case():
    # Guards against the budget being silently lowered back toward the lab default,
    # which is what let a single pathological request solve the level. See the module
    # docstring for how this number (1000) was chosen: the worst case measured against
    # a real model at the 600-byte cap was ~680 total tokens.
    assert lab.LEVELS[3].cost_budget_tokens > lab.COST_BUDGET_TOKENS
    assert lab.LEVELS[3].cost_budget_tokens >= 900


def test_unsupported_level_raises():
    with pytest.raises(ValueError):
        _run(99, "hello")


# --- scoring ----------------------------------------------------------------

def test_normal_summary_is_not_a_bypass(monkeypatch):
    _stub_llm(monkeypatch, prompt_tokens=120, output_tokens=80)
    result = _run(1, "a short support ticket")
    assert result["bypassed"] is False
    assert result["metrics"]["billed_tokens"] == 200
    assert result["metrics"]["budget_tokens"] == lab.COST_BUDGET_TOKENS


def test_long_output_bypasses_level2(monkeypatch):
    _stub_llm(monkeypatch, prompt_tokens=100, output_tokens=lab.COST_BUDGET_TOKENS)
    assert _run(2, "write forever")["bypassed"] is True


def test_oversized_input_bypasses_level1_even_with_a_short_reply(monkeypatch):
    _stub_llm(monkeypatch, prompt_tokens=lab.COST_BUDGET_TOKENS + 50, output_tokens=40)
    assert _run(1, "a very large paste")["bypassed"] is True


def test_billed_tokens_is_prompt_plus_output(monkeypatch):
    _stub_llm(monkeypatch, prompt_tokens=200, output_tokens=399)
    result = _run(1, "x")
    assert result["metrics"]["billed_tokens"] == 599
    assert result["bypassed"] is False


def test_budget_boundary_is_inclusive(monkeypatch):
    _stub_llm(monkeypatch, prompt_tokens=0, output_tokens=lab.COST_BUDGET_TOKENS)
    assert _run(1, "x")["bypassed"] is True


def test_generation_cap_is_flagged_only_when_generation_was_cut_off_at_it(monkeypatch):
    # Level 2 has no level-specific output cap, so its generation_cap_tokens falls
    # back to the host ceiling.
    _stub_llm(monkeypatch, prompt_tokens=50, output_tokens=lab.SAFETY_CEILING_TOKENS,
              done_reason="length")
    assert _run(2, "x")["metrics"]["generation_cap_hit"] is True

    _stub_llm(monkeypatch, prompt_tokens=50, output_tokens=lab.SAFETY_CEILING_TOKENS,
              done_reason="stop")
    assert _run(2, "x")["metrics"]["generation_cap_hit"] is False


def test_level3_generation_cap_is_its_own_level_specific_value(monkeypatch):
    assert lab.LEVELS[3].max_output_tokens < lab.SAFETY_CEILING_TOKENS
    _stub_llm(monkeypatch, prompt_tokens=50, output_tokens=lab.LEVELS[3].max_output_tokens,
              done_reason="length")
    result = _run(3, "x")
    assert result["metrics"]["generation_cap_tokens"] == lab.LEVELS[3].max_output_tokens
    assert result["metrics"]["generation_cap_hit"] is True


def test_rejected_input_never_reaches_the_model(monkeypatch):
    calls = _stub_llm(monkeypatch, prompt_tokens=1, output_tokens=1)
    result = _run(2, "x" * (lab.LEVELS[2].max_input_chars + 1))
    assert calls == []
    assert result["input_accepted"] is False
    assert result["bypassed"] is False
    assert result["metrics"]["billed_tokens"] == 0


def test_the_model_is_asked_to_stop_at_the_safety_ceiling(monkeypatch):
    seen = {}

    async def fake_chat(system_prompt, user_input, *, model, temperature, num_predict=None):
        seen["num_predict"] = num_predict
        return "ok", {"prompt_tokens": 1, "output_tokens": 1, "duration_ms": 0, "done_reason": "stop"}

    monkeypatch.setattr(lab, "chat_completion_with_stats", fake_chat)
    asyncio.run(lab.evaluate_level(1, "hello"))
    assert seen["num_predict"] == lab.SAFETY_CEILING_TOKENS


def test_level3_is_asked_to_stop_at_its_own_cap_not_the_host_ceiling(monkeypatch):
    seen = {}

    async def fake_chat(system_prompt, user_input, *, model, temperature, num_predict=None):
        seen["num_predict"] = num_predict
        return "ok", {"prompt_tokens": 1, "output_tokens": 1, "duration_ms": 0, "done_reason": "stop"}

    monkeypatch.setattr(lab, "chat_completion_with_stats", fake_chat)
    asyncio.run(lab.evaluate_level(3, "hello"))
    assert seen["num_predict"] == lab.LEVELS[3].max_output_tokens
    assert seen["num_predict"] < lab.SAFETY_CEILING_TOKENS


def test_a_level_output_cap_above_the_host_ceiling_is_clamped_down_to_it(monkeypatch):
    # Defensive: `challenge.max_output_tokens or SAFETY_CEILING_TOKENS` would silently
    # treat 0 as "unset", and a misconfigured level cap above the host ceiling would
    # never be clamped. Both are real failure modes for a config value someone edits
    # later, so pin the actual guard: min(level_cap, host_ceiling), `is not None`.
    import dataclasses
    seen = {}

    async def fake_chat(system_prompt, user_input, *, model, temperature, num_predict=None):
        seen["num_predict"] = num_predict
        return "ok", {"prompt_tokens": 1, "output_tokens": 1, "duration_ms": 0, "done_reason": "stop"}

    monkeypatch.setattr(lab, "chat_completion_with_stats", fake_chat)
    monkeypatch.setitem(lab.LEVELS, 3,
                        dataclasses.replace(lab.LEVELS[3],
                                           max_output_tokens=lab.SAFETY_CEILING_TOKENS + 500))
    lab.reset_concurrency_trackers()
    asyncio.run(lab.evaluate_level(3, "hello"))
    assert seen["num_predict"] == lab.SAFETY_CEILING_TOKENS


# --- Level 3: concurrency -----------------------------------------------------

def _slow_stub_llm(monkeypatch, *, delay_s, prompt_tokens=50, output_tokens=50):
    """Stand in for the LLM call with an artificial delay so concurrent evaluate_level
    calls genuinely overlap in time, exercising the real asyncio.Lock-protected
    tracker rather than asserting against mocked-out internals."""
    async def fake(system_prompt, user_input, model, temperature, num_predict):
        await asyncio.sleep(delay_s)
        return "generated text", {"prompt_tokens": prompt_tokens, "output_tokens": output_tokens,
                                   "duration_ms": int(delay_s * 1000), "done_reason": "stop"}

    monkeypatch.setattr(lab, "_call_llm", fake)


def test_level3_single_request_is_not_bypassed(monkeypatch):
    lab.reset_concurrency_trackers()
    _slow_stub_llm(monkeypatch, delay_s=0)
    result = _run(3, "a normal ticket")
    assert result["bypassed"] is False
    assert result["metrics"]["concurrent_requests"] == 1
    assert result["metrics"]["concurrency_budget"] == lab.LEVELS[3].concurrency_budget


def test_level3_concurrent_burst_bypasses_even_though_each_request_is_within_limits(monkeypatch):
    lab.reset_concurrency_trackers()
    budget = lab.LEVELS[3].concurrency_budget
    _slow_stub_llm(monkeypatch, delay_s=0.05)  # long enough that launching together overlaps

    async def fire_all():
        return await asyncio.gather(*[lab.evaluate_level(3, "ticket") for _ in range(budget)])

    results = asyncio.run(fire_all())
    # Every individual request stays under its own token and input limits.
    assert all(not r["metrics"]["generation_cap_hit"] for r in results)
    assert all(r["metrics"]["billed_tokens"] < r["metrics"]["budget_tokens"] for r in results)
    # But at least one of them observed the full concurrent pile-up and was bypassed.
    assert any(r["bypassed"] for r in results)
    assert max(r["metrics"]["concurrent_requests"] for r in results) == budget


def test_level3_sequential_requests_never_bypass_on_concurrency(monkeypatch):
    lab.reset_concurrency_trackers()
    _slow_stub_llm(monkeypatch, delay_s=0)
    results = [_run(3, "ticket") for _ in range(lab.LEVELS[3].concurrency_budget + 2)]
    assert all(not r["bypassed"] for r in results)
    assert all(r["metrics"]["concurrent_requests"] == 1 for r in results)


def test_level3_tracker_releases_the_slot_even_if_the_llm_call_raises(monkeypatch):
    lab.reset_concurrency_trackers()

    async def fake(system_prompt, user_input, model, temperature, num_predict):
        raise RuntimeError("backend exploded")

    monkeypatch.setattr(lab, "_call_llm", fake)
    with pytest.raises(RuntimeError):
        asyncio.run(lab.evaluate_level(3, "ticket"))

    # A fresh request afterwards should see concurrency 1, not a leaked, stuck slot.
    _slow_stub_llm(monkeypatch, delay_s=0)
    result = _run(3, "ticket")
    assert result["metrics"]["concurrent_requests"] == 1


def test_level3_trackers_are_independent_per_level(monkeypatch):
    lab.reset_concurrency_trackers()
    _slow_stub_llm(monkeypatch, delay_s=0.05)

    async def fire_mixed():
        return await asyncio.gather(
            lab.evaluate_level(1, "a"), lab.evaluate_level(2, "b"), lab.evaluate_level(3, "c"))

    r1, r2, r3 = asyncio.run(fire_mixed())
    # Levels 1 and 2 don't track concurrency at all.
    assert r1["metrics"]["concurrent_requests"] is None
    assert r2["metrics"]["concurrent_requests"] is None
    # Level 3 saw only itself -- concurrent traffic on levels 1/2 doesn't count against it.
    assert r3["metrics"]["concurrent_requests"] == 1


def test_host_capacity_ceiling_rejects_once_over_the_limit(monkeypatch):
    lab.reset_concurrency_trackers()
    # Prime the tracker just under the host ceiling without firing 50 real requests.
    tracker = lab._tracker_for(3)
    tracker._active = lab.HOST_MAX_IN_FLIGHT

    calls = []

    async def fake(system_prompt, user_input, model, temperature, num_predict):
        calls.append(1)
        return "x", {"prompt_tokens": 1, "output_tokens": 1, "duration_ms": 0, "done_reason": "stop"}

    monkeypatch.setattr(lab, "_call_llm", fake)
    result = _run(3, "ticket")

    assert result["input_accepted"] is False
    assert result["reason"] == "host_capacity_ceiling"
    assert result["bypassed"] is False
    assert calls == []  # rejected before ever reaching the model
    # The rejection released its own provisional slot: the tracker is back where it
    # was, not left one higher than where we primed it.
    assert tracker._active == lab.HOST_MAX_IN_FLIGHT


def test_host_capacity_ceiling_is_well_above_the_concurrency_budget():
    # The host ceiling exists to protect the host, not to be part of the challenge --
    # it must never be reachable by the number of requests that actually solve the level.
    assert lab.HOST_MAX_IN_FLIGHT > lab.LEVELS[3].concurrency_budget * 5


# --- Ollama client ----------------------------------------------------------

def _patch_ollama(monkeypatch, handler):
    real = httpx.AsyncClient

    def factory(*args, **kwargs):
        kwargs.pop("timeout", None)
        return real(transport=httpx.MockTransport(handler))

    monkeypatch.setattr(ollama_client.httpx, "AsyncClient", factory)


def test_stats_are_parsed_and_num_predict_is_sent(monkeypatch):
    sent = {}

    def handler(request):
        sent.update(__import__("json").loads(request.content))
        return httpx.Response(200, json={
            "message": {"content": "  a summary  "},
            "prompt_eval_count": 42,
            "eval_count": 17,
            "total_duration": 2_500_000_000,
            "done_reason": "length",
        })

    _patch_ollama(monkeypatch, handler)
    text, stats = asyncio.run(ollama_client.chat_completion_with_stats(
        "sys", "user", model="m", temperature=0.3, num_predict=64))

    assert text == "a summary"
    assert stats == {"prompt_tokens": 42, "output_tokens": 17,
                     "duration_ms": 2500, "done_reason": "length"}
    assert sent["options"] == {"temperature": 0.3, "num_predict": 64}
    assert sent["stream"] is False


def test_num_predict_is_omitted_when_not_given(monkeypatch):
    sent = {}

    def handler(request):
        sent.update(__import__("json").loads(request.content))
        return httpx.Response(200, json={"message": {"content": "x"}})

    _patch_ollama(monkeypatch, handler)
    _, stats = asyncio.run(ollama_client.chat_completion_with_stats(
        "s", "u", temperature=0.1))
    assert "num_predict" not in sent["options"]
    assert stats["prompt_tokens"] == 0 and stats["output_tokens"] == 0
