import asyncio

import httpx
import pytest

from src import ollama_client
from src.service.vulnerabilities import unbounded_consumption_lab as lab


def _stub_llm(monkeypatch, *, prompt_tokens, output_tokens, done_reason="stop"):
    calls = []

    async def fake(system_prompt, user_input, model, temperature):
        calls.append((system_prompt, user_input, model, temperature))
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


def test_safety_ceiling_is_flagged_only_when_generation_was_cut_off_at_it(monkeypatch):
    _stub_llm(monkeypatch, prompt_tokens=50, output_tokens=lab.SAFETY_CEILING_TOKENS,
              done_reason="length")
    assert _run(2, "x")["metrics"]["safety_ceiling_hit"] is True

    _stub_llm(monkeypatch, prompt_tokens=50, output_tokens=lab.SAFETY_CEILING_TOKENS,
              done_reason="stop")
    assert _run(2, "x")["metrics"]["safety_ceiling_hit"] is False


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
