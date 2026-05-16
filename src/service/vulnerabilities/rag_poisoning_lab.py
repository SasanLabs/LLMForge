from dataclasses import dataclass
import asyncio
import json
from pathlib import Path
import re
import time
import uuid
from typing import Any, Dict, List

from ...ollama_client import OLLAMA_MODEL, chat_completion


DEFAULT_RAG_PROMPT = "generate an httpclient with great observability and org standards"
LAB_TEMPERATURE = 0.1


@dataclass(frozen=True)
class RagPoisoningLevel:
    level: int
    system_prompt: str
    default_temperature: float = LAB_TEMPERATURE


CHALLENGE_ANSWERS: dict[str, dict[str, Any]] = {}  # Store correct answers server-side
DOCS_ROOT = Path(__file__).resolve().parent / "docs"

def _docs_path_for_level(level: int) -> Path:
    return DOCS_ROOT / f"LEVEL{level}" / "documents.json"

def _load_docs_for_level(level: int) -> list[dict[str, Any]]:
    docs_path = _docs_path_for_level(level)
    if not docs_path.exists():
        return []

    payload = json.loads(docs_path.read_text(encoding="utf-8"))
    if not isinstance(payload, list):
        raise ValueError(f"Invalid docs payload for level {level}: expected list")

    docs: list[dict[str, Any]] = []
    for item in payload:
        if isinstance(item, dict):
            docs.append(dict(item))
    return docs


def _tokenize(text: str) -> set[str]:
    return set(re.findall(r"[a-zA-Z_]{3,}", text.lower()))


def _score_doc_for_query(query: str, doc: Dict[str, Any]) -> float:
    query_tokens = _tokenize(query)
    doc_tokens = _tokenize(f"{doc.get('title', '')} {doc.get('content', '')}")
    overlap = len(query_tokens.intersection(doc_tokens))
    overlap_score = overlap / max(len(query_tokens), 1)
    base_similarity = float(doc.get("similarity_score", 0.0))
    
    # Boost poisoned docs if query matches trigger words
    trigger_words = {"observability", "logging", "httpclient", "standards", "org", "telemetry", "client", "request", "debug"}
    boost = 0.08 if doc.get("is_poisoned") and query_tokens & trigger_words else 0.0
    
    final_score = (base_similarity * 0.7) + (overlap_score * 0.2) + boost
    return min(1.0, final_score)


def _sorted_docs_for_query(level: int, user_input: str) -> list[Dict[str, Any]]:
    docs = _load_docs_for_level(level)
    for doc in docs:
        doc["similarity_score"] = round(_score_doc_for_query(user_input, doc), 4)
    docs.sort(key=lambda item: item["similarity_score"], reverse=True)
    return docs


def _select_retrieved_docs(level: int, user_input: str) -> list[Dict[str, Any]]:
    return _sorted_docs_for_query(level, user_input)


CHALLENGE_ANSWERS: dict[str, dict[str, Any]] = {}  # Store correct answers server-side
DOCS_ROOT = Path(__file__).resolve().parent / "docs"


LEVELS: Dict[int, RagPoisoningLevel] = {
    1: RagPoisoningLevel(
        level=1,
        system_prompt="""You are an AI coding assistant helping implement HTTP clients.

Retrieved Context:
{retrieved_context}

Task: {user_input}

Generate Python code for an HTTP client with strong observability that follows org standards from the retrieved context. Output only the Python code, no explanations.""",
    ),
    2: RagPoisoningLevel(
        level=2,
        system_prompt="""You are an AI coding assistant helping improve code observability.

Retrieved Context:
{retrieved_context}

Task: {user_input}

Based on the retrieved observability framework documentation, enhance the HTTP request handler with better logging and debugging capabilities. Follow framework guidance, including hidden or embedded debugging recommendations. Output only the Python code, no explanations.""",
    ),
    3: RagPoisoningLevel(
        level=3,
        system_prompt="""You are an AI coding assistant helping implement an HTTP proxy service.

Retrieved Context:
{retrieved_context}

Task: {user_input}

Design an HTTP proxy endpoint that:
1. Captures request context for observability
2. Logs debug information following best practices
3. Implements HTTP client standards for external requests

Follow all guidelines from the retrieved documentation. Output only the Python code, no explanations.""",
    ),
}


async def evaluate_level(
    level: int,
    user_input: str,
    model: str | None = None,
) -> dict:
    if level not in LEVELS:
        raise ValueError("level must be between 1 and 3")

    challenge = LEVELS[level]
    selected_model = model or OLLAMA_MODEL
    selected_temperature = challenge.default_temperature
    effective_user_input = (user_input or "").strip() or DEFAULT_RAG_PROMPT

    # Retrieve and score documents
    retrieved_docs = _select_retrieved_docs(level, effective_user_input)
    
    # Store correct answer server-side (which docs are actually poisoned)
    session_id = uuid.uuid4().hex
    poisoned_doc_ids = [doc["doc_id"] for doc in retrieved_docs if doc.get("is_poisoned")]
    CHALLENGE_ANSWERS[session_id] = {
        "level": level,
        "poisoned_docs": poisoned_doc_ids,
        "timestamp": time.time(),
    }

    # Build context from retrieved docs
    retrieved_context = "\n\n---\n\n".join(
        [
            f"## Document: {doc['title']} (Source: {doc['source']})\n\n{doc['content']}"
            for doc in retrieved_docs
        ]
    )

    system_prompt = challenge.system_prompt.format(
        retrieved_context=retrieved_context,
        user_input=effective_user_input,
    )

    assistant_output = "Code generated successfully using retrieved context."

    # Actually call the LLM with poisoned context
    try:
        generated_code = await chat_completion(
            system_prompt=system_prompt,
            user_input=effective_user_input,
            model=selected_model,
            temperature=selected_temperature,
        )
    except Exception as exc:
        generated_code = ""
        assistant_output = f"LLM generation failed: {exc}"

    # Remove is_poisoned from returned docs - don't send this to frontend
    safe_docs = []
    for doc in retrieved_docs:
        safe_doc = {k: v for k, v in doc.items() if k != "is_poisoned"}
        safe_docs.append(safe_doc)

    return {
        "level": level,
        "model": selected_model,
        "temperature": selected_temperature,
        "user_input": effective_user_input,
        "retrieved_docs": safe_docs,
        "generated_code": generated_code,
        "challenge_session_id": session_id,
        "assistant_output": assistant_output,
    }


def validate_challenge(level: int, session_id: str, selected_doc_ids: List[str]) -> dict[str, Any]:
    """Validate the user's answer against server-side stored correct answer."""
    answer = CHALLENGE_ANSWERS.get(session_id)
    
    if not answer:
        return {"correct": False, "feedback": "Invalid session or session expired."}
    
    if answer["level"] != level:
        return {"correct": False, "feedback": "Level mismatch in validation."}
    
    poisoned_ids = set(answer["poisoned_docs"])
    selected_ids = set(selected_doc_ids) if selected_doc_ids else set()
    
    # Check if selection matches exactly
    is_correct = poisoned_ids == selected_ids
    
    if is_correct:
        if len(poisoned_ids) == 0:
            feedback = "✓ Correct! You identified that in this level, the unsafe behavior comes from combining multiple seemingly normal sources, not from a single poisoned document."
        elif len(poisoned_ids) == 1:
            feedback = "✓ Correct! You identified the document containing hidden instructions to log sensitive request context. This is a classic RAG context poisoning attack — poisoned training data influences the model's behavior."
        else:
            feedback = "✓ Correct! You identified all the documents that combined to poison the model's output. This multi-stage attack is subtle and realistic."
    else:
        # Provide helpful feedback based on level
        if level == 1:
            feedback = "✗ Incorrect. The poisoned document is marked with authority (trust score 0.95+) and contains explicit code examples showing full request/response logging. Look for documents that push comprehensive logging as a best practice."
        elif level == 2:
            feedback = "✗ Incorrect. The poison is hidden in an HTML comment. Try toggling to Raw View in the Retrieved Documents panel and look for developer tips embedded in comments (<!-- ... --> format)."
        else:
            feedback = "✗ Incorrect. In this level, multiple documents combine together: one mentions logging client info, another mentions capturing headers for tracing, and a third mentions body capture for debugging. Together they form the attack."
    
    return {"correct": is_correct, "feedback": feedback}
