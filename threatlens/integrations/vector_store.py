"""Local persistent Chroma index for "similar past incidents".

Design rules:
* We supply our own embeddings (``embedding_function=None``), so Chroma never downloads a
  model.
* The collection name encodes the embedding model, and its metadata records the vector
  dimension. A mismatch is detected rather than mixing incompatible vectors.
* Chroma is an index only. Callers use the returned IDs to re-load and re-authorize records
  from SQLite.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Any, Protocol

log = logging.getLogger(__name__)


class Embedder(Protocol):
    model_name: str

    def embed(self, texts: list[str]) -> list[list[float]]: ...


class VectorStoreError(RuntimeError):
    pass


def collection_name(prefix: str, model: str) -> str:
    slug = re.sub(r"[^a-zA-Z0-9]+", "-", model).strip("-").lower()[:40] or "model"
    return f"{prefix}-{slug}"


class VectorStore:
    def __init__(self, path: Path, embedder: Embedder, *, prefix: str = "incidents") -> None:
        try:
            import chromadb
            from chromadb.config import Settings as ChromaSettings
        except ImportError as exc:  # optional dependency
            raise VectorStoreError("chromadb is not installed (pip install .[vector])") from exc
        self.embedder = embedder
        path.mkdir(parents=True, exist_ok=True)
        try:
            self._client = chromadb.PersistentClient(
                path=str(path),
                settings=ChromaSettings(anonymized_telemetry=False, allow_reset=False),
            )
            self.collection = self._client.get_or_create_collection(
                name=collection_name(prefix, embedder.model_name),
                configuration={"hnsw": {"space": "cosine"}},
                metadata={"embed_model": embedder.model_name},
                embedding_function=None,
            )
        except Exception as exc:  # chromadb raises a variety of internal errors
            raise VectorStoreError(f"could not open vector store: {type(exc).__name__}") from exc

    def _check_dims(self, vectors: list[list[float]]) -> None:
        dims = len(vectors[0])
        meta = self.collection.metadata or {}
        stored = meta.get("dims")
        if stored is None:
            self.collection.modify(metadata={**meta, "dims": dims})
        elif int(stored) != dims:
            raise VectorStoreError(
                f"embedding dimension {dims} does not match collection ({stored}); reindex"
            )

    def upsert(self, items: list[tuple[str, str, dict[str, Any]]]) -> None:
        """items: (id, document, metadata)."""
        if not items:
            return
        vectors = self.embedder.embed([doc for _, doc, _ in items])
        self._check_dims(vectors)
        self.collection.upsert(
            ids=[i for i, _, _ in items],
            embeddings=vectors,  # type: ignore[arg-type]
            documents=[d for _, d, _ in items],
            metadatas=[m for _, _, m in items],
        )

    def delete(self, ids: list[str]) -> None:
        if ids:
            self.collection.delete(ids=ids)

    def clear(self) -> None:
        existing = self.collection.get(include=[])["ids"]
        self.delete(list(existing))

    def query(self, text: str, k: int) -> list[tuple[str, float, dict[str, Any]]]:
        if self.collection.count() == 0:
            return []
        vector = self.embedder.embed([text])
        self._check_dims(vector)
        res = self.collection.query(
            query_embeddings=vector,  # type: ignore[arg-type]  # chroma stubs: numpy-centric
            n_results=k,
            include=["metadatas", "distances"],
        )
        ids = res["ids"][0]
        distances = (res.get("distances") or [[]])[0]
        metas = (res.get("metadatas") or [[]])[0]
        return [(ids[i], float(distances[i]), dict(metas[i] or {})) for i in range(len(ids))]

    def count(self) -> int:
        return int(self.collection.count())


class OllamaEmbedder:
    def __init__(self, client: Any, model_name: str) -> None:
        self.client = client
        self.model_name = model_name

    def embed(self, texts: list[str]) -> list[list[float]]:
        return list(self.client.embed(model=self.model_name, texts=texts))
