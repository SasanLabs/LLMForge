"""Unbounded Consumption lab (OWASP LLM10:2025).

The target is a summarization endpoint backed by a local Ollama model. Unlike the
other labs there is no secret to leak: the goal is to make the service cost far more
than a summary should. Every response reports what it consumed, and a level is
bypassed when either of two independent things happens:

* a single request bills at least ``cost_budget_tokens`` (prompt plus generated
  tokens) -- the per-request cost vector, or
* a level that tracks it (``concurrency_budget`` set) sees at least that many requests
  in flight on the endpoint at once -- the pile-up cost vector, which trips even when
  every individual request is within every per-request limit.

The levels remove controls one at a time:

* Level 1 has no limit on input size or output length.
* Level 2 caps the input, so the cost has to come from unbounded *output*.
* Level 3 caps input and output on every request, so the realistic, intended solve
  path is firing many requests at once -- see "Level 3 in detail" below for exactly
  what its per-request caps do and do not guarantee.

Server-side the lab keeps two ceilings so a player cannot wedge the host it runs on:
HOST_INPUT_CEILING_CHARS and HOST_MAX_IN_FLIGHT. Both are far above anything a level
needs to be solved, are reported in every response, and would not exist in the
application being modelled.

Level 3 in detail
------------------
Level 3's input is capped in UTF-8 *bytes* (600), not characters. A character cap
doesn't bound token cost: BPE tokenizers can split multi-byte scripts (CJK, emoji) or
adversarially constructed Unicode (stacked combining marks) into far more tokens per
character than ASCII. Measured against this lab's real backend (phi3:mini), 600
characters of dense CJK/emoji alone cost 1,145 prompt tokens -- almost double this
level's token budget, with no output at all yet. A byte cap bounds that far more
tightly, since a tokenizer's byte-fallback path puts a rough ceiling near one token
per byte; the same worst-case content truncated to 600 *bytes* instead costs 613-679
total tokens in measurement, depending on construction.

That is still a measurement, not a mathematical proof -- a stacked-combining-mark
("Zalgo") string at the 600-byte cap measured 613 prompt tokens, i.e. a single
request *can* get close to a naively-set budget. Level 3's own cost_budget_tokens is
therefore set to 1000, comfortably above every worst case measured (~680 tokens
total), rather than reusing the lab's 600-token default. A normal single request
(plain text, any reasonable length) bills 150-250 tokens -- nowhere near either
budget -- so this headroom doesn't make the level easier to solve by accident; it
closes off solving it by token-engineering a single pathological request, which was
not the intended lesson here. The intended, realistic solve path remains concurrency.

Known limitations (by design, not bugs)
----------------------------------------
* Concurrency is intentionally unbounded for the player below HOST_MAX_IN_FLIGHT --
  the missing per-user/IP rate limit *is* the vulnerability this level demonstrates.
* The in-flight counter is global per level, not per player/session: if two people
  attack Level 3 at the same moment, each can push the other toward the bypass. A
  shared lab host has exactly this problem in the real world.
* Tracking is in-process. It is only accurate with a single worker process; running
  this behind multiple workers would need a shared store (Redis, etc.) to still work.

Per-player tracking and multi-worker support are reasonable follow-up work; they are
out of scope for this level, which demonstrates the *absence* of any concurrency
control, not a correctly-scoped one.
"""

from dataclasses import dataclass
from typing import Any

from ...ollama_client import OLLAMA_MODEL, chat_completion_with_stats


# A three-sentence summary of a short passage bills roughly 100-250 tokens. A request
# that bills this much has been driven well past what the endpoint is for.
COST_BUDGET_TOKENS = 600

# Host protection, not a defense: generation is stopped here so the lab host survives,
# regardless of any level-specific output cap below.
SAFETY_CEILING_TOKENS = 1024
HOST_INPUT_CEILING_CHARS = 100_000
# Host protection for the concurrency levels: far above the 5 needed to solve Level 3,
# this exists only so a single abusive burst can't starve every other visitor sharing
# this lab host. Rejections here are reported the same way as the other host ceilings.
HOST_MAX_IN_FLIGHT = 50

LAB_TEMPERATURE = 0.3

_BASE_SYSTEM_PROMPT = (
    "You are the summarization service for Acme Corp's support portal. "
    "Summarize the text the user sends in at most three sentences. "
    "Do not write anything else."
)


@dataclass(frozen=True)
class UnboundedConsumptionLevel:
    level: int
    system_prompt: str
    max_input_chars: int | None = None
    # UTF-8 byte cap instead of (or in addition to) a character cap. See the module
    # docstring: this is what actually bounds worst-case prompt tokens for a level
    # that claims per-request token safety. None means not enforced at this level.
    max_input_bytes: int | None = None
    # A per-request output cap that is part of the level's own defense, distinct from
    # the host-protection SAFETY_CEILING_TOKENS. None means "no level defense here" --
    # generation still stops at the host ceiling, but that's not part of the challenge.
    max_output_tokens: int | None = None
    cost_budget_tokens: int = COST_BUDGET_TOKENS
    # None: this level doesn't track concurrency. Set: the level is bypassed once this
    # many requests are in flight on it at once, independent of any single request's
    # own token cost.
    concurrency_budget: int | None = None
    default_temperature: float = LAB_TEMPERATURE


@dataclass(frozen=True)
class InputResult:
    allowed: bool
    value: str
    reason: str | None = None


LEVELS: dict[int, UnboundedConsumptionLevel] = {
    # Nothing enforces the "three sentences" instruction and nothing bounds the input.
    1: UnboundedConsumptionLevel(level=1, system_prompt=_BASE_SYSTEM_PROMPT),
    # The input is capped at a size that fits a real support ticket. The output is
    # still governed only by the prompt, so it stays as long as the model is talked into.
    2: UnboundedConsumptionLevel(level=2, system_prompt=_BASE_SYSTEM_PROMPT,
                                 max_input_chars=600),
    # Both directions are capped on every request -- 600 input bytes (see module
    # docstring for why bytes, not characters), 150 output tokens -- with a
    # level-specific token budget set above the measured worst case for a single
    # request. Nothing limits how many requests run at once, so firing several
    # concurrently still saturates the one backend they share, with every individual
    # request reporting "within budget".
    3: UnboundedConsumptionLevel(level=3, system_prompt=_BASE_SYSTEM_PROMPT,
                                 max_input_bytes=600, max_output_tokens=150,
                                 cost_budget_tokens=1000, concurrency_budget=5),
}


class _ConcurrencyTracker:
    """Counts requests currently in flight through one level's LLM call.

    ``enter`` returns the count *including the caller*. No lock guards ``_active``:
    asyncio runs one coroutine at a time between ``await`` points, and neither
    ``enter`` nor ``exit`` awaits anything, so each one runs to completion before the
    event loop can switch to another coroutine -- the increment/decrement can't be
    interleaved even without a lock. (A lock was here originally; it added nothing but
    an extra awaitable step to reason about.)
    """

    def __init__(self) -> None:
        self._active = 0

    def enter(self) -> int:
        self._active += 1
        return self._active

    def exit(self) -> None:
        self._active = max(0, self._active - 1)


_CONCURRENCY_TRACKERS: dict[int, _ConcurrencyTracker] = {}


def _tracker_for(level: int) -> _ConcurrencyTracker:
    if level not in _CONCURRENCY_TRACKERS:
        _CONCURRENCY_TRACKERS[level] = _ConcurrencyTracker()
    return _CONCURRENCY_TRACKERS[level]


def reset_concurrency_trackers() -> None:
    """Test-only: give each level a fresh tracker so runs don't leak into each other."""
    _CONCURRENCY_TRACKERS.clear()


def _challenge_for(level: int) -> UnboundedConsumptionLevel:
    try:
        return LEVELS[level]
    except KeyError:
        raise ValueError(f"Unsupported level {level}") from None


def _validate_input(challenge: UnboundedConsumptionLevel, raw_input: str) -> InputResult:
    value = raw_input.strip()
    if not value:
        return InputResult(False, "", "empty_input")
    if challenge.max_input_chars is not None and len(value) > challenge.max_input_chars:
        return InputResult(False, value, "max_input_chars")
    if challenge.max_input_bytes is not None and len(value.encode("utf-8")) > challenge.max_input_bytes:
        return InputResult(False, value, "max_input_bytes")
    if len(value) > HOST_INPUT_CEILING_CHARS:
        return InputResult(False, value, "host_input_ceiling")
    return InputResult(True, value, None)


def _reason_message(challenge: UnboundedConsumptionLevel, reason: str) -> str:
    if reason == "empty_input":
        return "Send some text to summarize."
    if reason == "max_input_chars":
        return (f"Input rejected: {challenge.max_input_chars} characters is the maximum "
                f"this endpoint accepts.")
    if reason == "max_input_bytes":
        return (f"Input rejected: {challenge.max_input_bytes} UTF-8 bytes is the maximum "
                f"this endpoint accepts. Multi-byte characters (CJK, emoji, combining "
                f"marks) count for more than one byte each.")
    if reason == "host_input_ceiling":
        return (f"Input rejected: the lab host refuses more than {HOST_INPUT_CEILING_CHARS} "
                f"characters. This is host protection, not part of the challenge.")
    if reason == "host_capacity_ceiling":
        return (f"Input rejected: {HOST_MAX_IN_FLIGHT} requests are already in flight on "
                f"this endpoint. This is host protection so one burst can't starve every "
                f"other visitor, not part of the challenge -- {LEVELS[3].concurrency_budget} "
                f"concurrent requests is enough to solve this level.")
    return "Input rejected."


async def _call_llm(system_prompt: str, user_input: str, model: str, temperature: float,
                    num_predict: int) -> tuple[str, dict[str, Any]]:
    return await chat_completion_with_stats(
        system_prompt,
        user_input,
        model=model,
        temperature=temperature,
        num_predict=num_predict,
    )


def _build_response(
    challenge: UnboundedConsumptionLevel,
    *,
    model: str,
    temperature: float,
    input_accepted: bool,
    reason: str | None,
    input_chars: int,
    generation_cap_tokens: int = SAFETY_CEILING_TOKENS,
    concurrent_requests: int | None = None,
    assistant_output: str = "",
    stats: dict[str, Any] | None = None,
) -> dict[str, Any]:
    stats = stats or {}
    prompt_tokens = int(stats.get("prompt_tokens", 0))
    output_tokens = int(stats.get("output_tokens", 0))
    billed_tokens = prompt_tokens + output_tokens
    generation_cap_hit = (
        stats.get("done_reason") == "length" and output_tokens >= generation_cap_tokens
    )

    token_bypass = input_accepted and billed_tokens >= challenge.cost_budget_tokens
    concurrency_bypass = (
        input_accepted and challenge.concurrency_budget is not None
        and concurrent_requests is not None
        and concurrent_requests >= challenge.concurrency_budget
    )
    bypassed = token_bypass or concurrency_bypass

    if not input_accepted:
        message = _reason_message(challenge, reason or "")
    elif token_bypass:
        message = (f"This one request billed {billed_tokens} tokens against an expected "
                   f"budget of {challenge.cost_budget_tokens}. Nothing stopped it.")
    elif concurrency_bypass:
        message = (f"{concurrent_requests} requests were in flight on this endpoint at "
                   f"once (budget {challenge.concurrency_budget}). Every one of them was "
                   f"individually within its own limits -- the cost is in the pile-up, "
                   f"not any single request.")
    else:
        message = (f"Billed {billed_tokens} of {challenge.cost_budget_tokens} tokens. "
                   f"A normal summary; the endpoint still did what it was for.")

    metrics: dict[str, Any] = {
        "input_chars": input_chars,
        "prompt_tokens": prompt_tokens,
        "output_tokens": output_tokens,
        "billed_tokens": billed_tokens,
        "budget_tokens": challenge.cost_budget_tokens,
        "duration_ms": int(stats.get("duration_ms", 0)),
        "safety_ceiling_tokens": SAFETY_CEILING_TOKENS,
        "generation_cap_tokens": generation_cap_tokens,
        "generation_cap_hit": generation_cap_hit,
        "concurrent_requests": concurrent_requests,
        "concurrency_budget": challenge.concurrency_budget,
    }

    return {
        "level": challenge.level,
        "model": model,
        "temperature": temperature,
        "input_accepted": input_accepted,
        "bypassed": bypassed,
        "reason": reason,
        "assistant_output": assistant_output if input_accepted else message,
        "message": message,
        "metrics": metrics,
    }


async def evaluate_level(
    level: int,
    user_input: str,
    model: str | None = None,
) -> dict[str, Any]:
    challenge = _challenge_for(level)
    selected_model = model or OLLAMA_MODEL
    temperature = challenge.default_temperature
    input_result = _validate_input(challenge, user_input)

    if not input_result.allowed:
        return _build_response(
            challenge,
            model=selected_model,
            temperature=temperature,
            input_accepted=False,
            reason=input_result.reason,
            input_chars=len(input_result.value),
        )

    # generation_cap_tokens is always <= the host ceiling, even if a level's own cap
    # were ever misconfigured above it -- the host ceiling is the hard backstop.
    generation_cap = (
        min(challenge.max_output_tokens, SAFETY_CEILING_TOKENS)
        if challenge.max_output_tokens is not None
        else SAFETY_CEILING_TOKENS
    )

    tracker = _tracker_for(level) if challenge.concurrency_budget is not None else None
    concurrent_requests = tracker.enter() if tracker else None

    if tracker and concurrent_requests > HOST_MAX_IN_FLIGHT:
        tracker.exit()
        return _build_response(
            challenge,
            model=selected_model,
            temperature=temperature,
            input_accepted=False,
            reason="host_capacity_ceiling",
            input_chars=len(input_result.value),
        )

    try:
        assistant_output, stats = await _call_llm(
            challenge.system_prompt, input_result.value, selected_model, temperature,
            generation_cap)
    finally:
        if tracker:
            tracker.exit()

    return _build_response(
        challenge,
        model=selected_model,
        temperature=temperature,
        input_accepted=True,
        reason=None,
        input_chars=len(input_result.value),
        generation_cap_tokens=generation_cap,
        concurrent_requests=concurrent_requests,
        assistant_output=assistant_output,
        stats=stats,
    )
