from typing import Any
from uuid import uuid4

import httpx
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from ..ollama_client import OLLAMA_EMBED_MODEL, embed_texts
from ..vector_search import vector_store

router = APIRouter(prefix="/api/v1/vector", tags=["vector-search"])


class VectorDocument(BaseModel):
    id: str | None = Field(default=None, max_length=120)
    text: str = Field(..., min_length=1, max_length=20000)
    metadata: dict[str, Any] = Field(default_factory=dict)


class UpsertDocumentsRequest(BaseModel):
    documents: list[VectorDocument] = Field(..., min_length=1, max_length=128)


class SearchRequest(BaseModel):
    query: str = Field(..., min_length=1, max_length=5000)
    top_k: int = Field(default=3, ge=1, le=20)


def _runtime_error(exc: Exception) -> HTTPException:
    if isinstance(exc, ValueError):
        return HTTPException(status_code=400, detail=str(exc))
    if isinstance(exc, httpx.HTTPStatusError):
        return HTTPException(status_code=502, detail=f"Ollama returned {exc.response.status_code}")
    if isinstance(exc, httpx.RequestError):
        return HTTPException(status_code=503, detail="Ollama is not reachable yet. Wait and try again.")
    return HTTPException(status_code=500, detail="Unexpected vector service error")


@router.get("/status")
async def vector_status() -> dict[str, Any]:
    return vector_store.status()


@router.post("/documents")
async def upsert_documents(payload: UpsertDocumentsRequest) -> dict[str, Any]:
    try:
        normalized_documents = [
            {
                "id": item.id or str(uuid4()),
                "text": item.text.strip(),
                "metadata": item.metadata,
            }
            for item in payload.documents
        ]
        embeddings = await embed_texts([item["text"] for item in normalized_documents])
        result = vector_store.add(normalized_documents, embeddings)
        result["embedding_model"] = OLLAMA_EMBED_MODEL
        return result
    except Exception as exc:
        raise _runtime_error(exc) from exc


@router.post("/search")
async def search_documents(payload: SearchRequest) -> dict[str, Any]:
    try:
        embeddings = await embed_texts([payload.query.strip()])
        matches = vector_store.search(embeddings, payload.top_k)
        return {
            "query": payload.query,
            "top_k": payload.top_k,
            "embedding_model": OLLAMA_EMBED_MODEL,
            "matches": matches,
        }
    except Exception as exc:
        raise _runtime_error(exc) from exc


@router.delete("/documents")
async def reset_documents() -> dict[str, Any]:
    return vector_store.reset()