import os

import httpx
import numpy as np


OLLAMA_URL = os.getenv("OLLAMA_URL", "http://127.0.0.1:11434")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "phi3:mini")
OLLAMA_EMBED_MODEL = os.getenv("OLLAMA_EMBED_MODEL", "nomic-embed-text")
OLLAMA_TIMEOUT_SECONDS = float(os.getenv("OLLAMA_TIMEOUT_SECONDS", "90"))


def _normalize_embedding_matrix(vectors: list[list[float]] | np.ndarray) -> np.ndarray:
    matrix = np.asarray(vectors, dtype="float32")
    if matrix.ndim != 2:
        raise ValueError("embedding response must be a 2D array")
    if matrix.shape[1] == 0:
        raise ValueError("embedding response must include at least one dimension")
    return matrix


def _extract_chat_content(payload: dict) -> str:
    content = payload.get("message", {}).get("content", "")
    if isinstance(content, str):
        return content.strip()
    return str(content)


async def chat_completion(system_prompt: str, user_input: str, *, model: str | None = None, temperature: float) -> str:
    payload = {
        "model": model or OLLAMA_MODEL,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_input},
        ],
        "stream": False,
        "options": {"temperature": temperature},
    }

    async with httpx.AsyncClient(timeout=OLLAMA_TIMEOUT_SECONDS) as client:
        response = await client.post(f"{OLLAMA_URL}/api/chat", json=payload)
        response.raise_for_status()
        return _extract_chat_content(response.json())


async def _embed_with_modern_api(client: httpx.AsyncClient, texts: list[str], model: str) -> np.ndarray:
    response = await client.post(
        f"{OLLAMA_URL}/api/embed",
        json={"model": model, "input": texts},
    )
    response.raise_for_status()
    payload = response.json()
    embeddings = payload.get("embeddings")
    if not isinstance(embeddings, list) or not embeddings:
        raise ValueError("Ollama embed API returned no embeddings")
    return _normalize_embedding_matrix(embeddings)


async def _embed_with_legacy_api(client: httpx.AsyncClient, texts: list[str], model: str) -> np.ndarray:
    embeddings: list[list[float]] = []
    for text in texts:
        response = await client.post(
            f"{OLLAMA_URL}/api/embeddings",
            json={"model": model, "prompt": text},
        )
        response.raise_for_status()
        payload = response.json()
        embedding = payload.get("embedding")
        if not isinstance(embedding, list) or not embedding:
            raise ValueError("Ollama legacy embeddings API returned no embedding")
        embeddings.append(embedding)
    return _normalize_embedding_matrix(embeddings)


async def embed_texts(texts: list[str], *, model: str | None = None) -> np.ndarray:
    if not texts:
        raise ValueError("at least one text is required")

    selected_model = model or OLLAMA_EMBED_MODEL
    async with httpx.AsyncClient(timeout=OLLAMA_TIMEOUT_SECONDS) as client:
        try:
            return await _embed_with_modern_api(client, texts, selected_model)
        except httpx.HTTPStatusError as exc:
            if exc.response.status_code != 404:
                raise
        return await _embed_with_legacy_api(client, texts, selected_model)