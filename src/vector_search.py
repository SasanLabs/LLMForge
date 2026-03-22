import json
import os
from pathlib import Path
from threading import RLock
from typing import Any

import faiss
import numpy as np

from .ollama_client import OLLAMA_EMBED_MODEL, embed_texts


_default_data_dir = Path(__file__).resolve().parent.parent / "data"
VECTOR_DATA_DIR = Path(os.getenv("VECTOR_DATA_DIR", str(_default_data_dir)))
VECTOR_INDEX_PATH = Path(os.getenv("VECTOR_INDEX_PATH", str(VECTOR_DATA_DIR / "faiss.index")))
VECTOR_DOCSTORE_PATH = Path(os.getenv("VECTOR_DOCSTORE_PATH", str(VECTOR_DATA_DIR / "faiss-docstore.json")))


def normalize_matrix(vectors: list[list[float]] | np.ndarray) -> np.ndarray:
    matrix = np.asarray(vectors, dtype="float32")
    if matrix.ndim != 2:
        raise ValueError("embedding response must be a 2D array")
    if matrix.shape[1] == 0:
        raise ValueError("embedding response must include at least one dimension")
    return matrix


class FaissVectorStore:
    def __init__(self) -> None:
        self._lock = RLock()
        self._index: faiss.Index | None = None
        self._documents: list[dict[str, Any]] = []
        self._dimension: int | None = None
        self._load()

    def _load(self) -> None:
        with self._lock:
            if not VECTOR_DOCSTORE_PATH.exists():
                return

            self._documents = json.loads(VECTOR_DOCSTORE_PATH.read_text(encoding="utf-8"))
            if VECTOR_INDEX_PATH.exists():
                self._index = faiss.read_index(str(VECTOR_INDEX_PATH))
                self._dimension = self._index.d

    def _save(self) -> None:
        VECTOR_DATA_DIR.mkdir(parents=True, exist_ok=True)
        VECTOR_DOCSTORE_PATH.write_text(json.dumps(self._documents, indent=2), encoding="utf-8")
        if self._index is not None:
            faiss.write_index(self._index, str(VECTOR_INDEX_PATH))

    def add(self, documents: list[dict[str, Any]], embeddings: np.ndarray) -> dict[str, Any]:
        matrix = normalize_matrix(embeddings)

        with self._lock:
            if len(documents) != matrix.shape[0]:
                raise ValueError("document count must match embedding count")

            if self._index is None:
                self._dimension = int(matrix.shape[1])
                self._index = faiss.IndexFlatIP(self._dimension)
            elif self._dimension != int(matrix.shape[1]):
                raise ValueError(
                    f"embedding dimension mismatch: expected {self._dimension}, got {matrix.shape[1]}"
                )

            faiss.normalize_L2(matrix)
            self._index.add(matrix)
            self._documents.extend(documents)
            self._save()

            return {
                "added": len(documents),
                "total_documents": len(self._documents),
                "dimension": self._dimension,
            }

    def search(self, embedding: np.ndarray, top_k: int) -> list[dict[str, Any]]:
        matrix = normalize_matrix(embedding)

        with self._lock:
            if self._index is None or not self._documents:
                return []
            if matrix.shape[0] != 1:
                raise ValueError("search expects exactly one embedding vector")
            if self._dimension != int(matrix.shape[1]):
                raise ValueError(
                    f"embedding dimension mismatch: expected {self._dimension}, got {matrix.shape[1]}"
                )

            faiss.normalize_L2(matrix)
            limit = min(top_k, len(self._documents))
            scores, indices = self._index.search(matrix, limit)

            matches: list[dict[str, Any]] = []
            for score, index in zip(scores[0], indices[0]):
                if index < 0:
                    continue
                document = self._documents[index]
                matches.append(
                    {
                        "id": document["id"],
                        "text": document["text"],
                        "metadata": document.get("metadata", {}),
                        "score": float(score),
                    }
                )
            return matches

    def reset(self) -> dict[str, Any]:
        with self._lock:
            self._index = None
            self._documents = []
            self._dimension = None
            if VECTOR_INDEX_PATH.exists():
                VECTOR_INDEX_PATH.unlink()
            if VECTOR_DOCSTORE_PATH.exists():
                VECTOR_DOCSTORE_PATH.unlink()
            return {"cleared": True, "total_documents": 0}

    def status(self) -> dict[str, Any]:
        with self._lock:
            return {
                "embedding_model": OLLAMA_EMBED_MODEL,
                "total_documents": len(self._documents),
                "dimension": self._dimension,
                "index_path": str(VECTOR_INDEX_PATH),
                "docstore_path": str(VECTOR_DOCSTORE_PATH),
            }


vector_store = FaissVectorStore()