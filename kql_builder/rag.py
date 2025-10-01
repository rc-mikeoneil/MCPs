"""Lightweight retrieval-augmented generation helpers for Defender schema."""
from __future__ import annotations

import hashlib
import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

try:  # pragma: no cover - import guard
    import faiss  # type: ignore
except ImportError as exc:  # pragma: no cover - handled at runtime
    faiss = None  # type: ignore[assignment]
    _FAISS_IMPORT_ERROR = exc
else:
    _FAISS_IMPORT_ERROR = None

try:  # pragma: no cover - import guard
    import numpy as np
except ImportError as exc:  # pragma: no cover - handled at runtime
    np = None  # type: ignore[assignment]
    _NUMPY_IMPORT_ERROR = exc
else:
    _NUMPY_IMPORT_ERROR = None

try:  # pragma: no cover - import guard
    from sentence_transformers import SentenceTransformer
except ImportError as exc:  # pragma: no cover - handled at runtime
    SentenceTransformer = None  # type: ignore[assignment]
    _SENTENCE_TRANSFORMERS_IMPORT_ERROR = exc
else:
    _SENTENCE_TRANSFORMERS_IMPORT_ERROR = None

try:  # pragma: no cover - import guard
    from rapidfuzz import process as rapidfuzz_process
except ImportError:  # pragma: no cover - handled at runtime
    rapidfuzz_process = None  # type: ignore[assignment]

from schema_scraper import SchemaCache

logger = logging.getLogger(__name__)


@dataclass
class RAGService:
    """Build and reuse embeddings for Defender schema documentation."""

    schema_cache: SchemaCache
    cache_dir: Path = field(default_factory=lambda: Path(".cache"))
    model_name: str = "sentence-transformers/all-MiniLM-L6-v2"

    def __post_init__(self) -> None:
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self._model: Optional[SentenceTransformer] = None
        self._index: Optional[Any] = None
        self._documents: List[Dict[str, str]] = []
        self._dimension: Optional[int] = None
        self._metadata_path = self.cache_dir / "rag_metadata.json"
        self._index_path = self.cache_dir / "rag_index.faiss"
        self._mode: str = "uninitialized"

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------
    def _load_model(self) -> SentenceTransformer:
        if SentenceTransformer is None:
            raise RuntimeError(
                "sentence-transformers is required for retrieval. Install the optional dependencies."
            ) from _SENTENCE_TRANSFORMERS_IMPORT_ERROR
        if self._model is None:
            logger.info("Loading sentence transformer model '%s'", self.model_name)
            self._model = SentenceTransformer(self.model_name)
        return self._model

    def _build_documents(self, schema: Dict[str, Dict[str, object]]) -> List[Dict[str, str]]:
        documents: List[Dict[str, str]] = []
        for table in sorted(schema.keys()):
            table_info = schema.get(table, {})
            url = str(table_info.get("url", ""))
            columns = table_info.get("columns", []) or []

            column_lines: List[str] = []
            for column in columns:  # type: ignore[assignment]
                name = str(column.get("name", "")) if isinstance(column, dict) else ""
                ctype = str(column.get("type", "")) if isinstance(column, dict) else ""
                description = str(column.get("description", "")) if isinstance(column, dict) else ""
                parts = [part for part in [name, f"({ctype})" if ctype else "", description] if part]
                if parts:
                    column_lines.append(" ".join(parts))

            if not column_lines:
                column_lines.append("No column metadata available.")

            text = "\n".join(
                [
                    f"Table: {table}",
                    f"Documentation: {url}" if url else "Documentation: (missing)",
                    "Columns:",
                    *column_lines,
                ]
            )

            documents.append(
                {
                    "id": table,
                    "table": table,
                    "url": url,
                    "text": text,
                }
            )
        return documents

    def _documents_signature(self, documents: List[Dict[str, str]]) -> str:
        payload = json.dumps(
            [{"table": doc["table"], "url": doc["url"], "text": doc["text"]} for doc in documents],
            sort_keys=True,
        ).encode("utf-8")
        return hashlib.sha256(payload).hexdigest()

    def _load_cached_index(self, signature: str) -> bool:
        if not self._metadata_path.exists() or not self._index_path.exists():
            return False

        try:
            with self._metadata_path.open("r", encoding="utf-8") as handle:
                metadata = json.load(handle)
        except Exception as exc:  # pragma: no cover - defensive
            logger.warning("Failed to read RAG metadata cache: %s", exc)
            return False

        if metadata.get("signature") != signature:
            logger.info("Cached embeddings are out of date; rebuilding.")
            return False

        mode = metadata.get("mode", "faiss")
        self._mode = mode
        self._documents = metadata.get("documents", [])

        if mode == "fuzzy":
            logger.info("Loaded fallback retrieval metadata for %d documents.", len(self._documents))
            self._index = None
            self._dimension = None
            return True

        if faiss is None:
            return False

        try:
            self._index = faiss.read_index(str(self._index_path))
        except Exception as exc:  # pragma: no cover - defensive
            logger.warning("Failed to read FAISS index: %s", exc)
            self._index = None
            return False

        self._dimension = metadata.get("dimension")
        if self._dimension is None:
            logger.warning("Cached metadata missing embedding dimension; rebuilding.")
            self._index = None
            self._documents = []
            return False

        logger.info("Loaded cached embeddings for %d documents.", len(self._documents))
        return True

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def ensure_index(self, force: bool = False) -> None:
        """Ensure the embedding index exists for the Defender schema."""

        schema = self.schema_cache.load_or_refresh()
        documents = self._build_documents(schema)
        signature = self._documents_signature(documents)

        if not force and self._load_cached_index(signature):
            return

        if SentenceTransformer is None or faiss is None or np is None:
            if rapidfuzz_process is None:
                raise RuntimeError(
                    "Retrieval dependencies are unavailable and rapidfuzz fallback is missing."
                )
            logger.warning(
                "Embedding libraries unavailable; using rapidfuzz-based fallback retrieval."
            )
            self._documents = documents
            self._dimension = None
            self._index = None
            self._mode = "fuzzy"
            with self._metadata_path.open("w", encoding="utf-8") as handle:
                json.dump(
                    {
                        "signature": signature,
                        "mode": "fuzzy",
                        "documents": documents,
                    },
                    handle,
                    ensure_ascii=False,
                    indent=2,
                )
            if self._index_path.exists():
                self._index_path.unlink()
            return

        self._mode = "faiss"
        model = self._load_model()
        logger.info("Generating embeddings for %d schema documents", len(documents))
        embeddings = model.encode(
            [doc["text"] for doc in documents],
            convert_to_numpy=True,
            normalize_embeddings=True,
            show_progress_bar=False,
        ).astype(np.float32)

        if embeddings.ndim != 2:
            raise ValueError("Model returned embeddings with unexpected shape")

        dimension = embeddings.shape[1]
        index = faiss.IndexFlatIP(dimension)
        index.add(embeddings)

        faiss.write_index(index, str(self._index_path))
        with self._metadata_path.open("w", encoding="utf-8") as handle:
            json.dump(
                {
                    "signature": signature,
                    "mode": "faiss",
                    "dimension": dimension,
                    "documents": documents,
                },
                handle,
                ensure_ascii=False,
                indent=2,
            )

        self._index = index
        self._documents = documents
        self._dimension = dimension
        logger.info("Persisted new embeddings cache to %s", self.cache_dir)

    def search(self, query: str, k: int = 5) -> List[Dict[str, object]]:
        """Return the top-k documents matching the query."""

        if not query or not query.strip():
            raise ValueError("Query must be a non-empty string")

        self.ensure_index()
        top_k = min(k, len(self._documents))
        if top_k == 0:
            return []

        if self._mode == "fuzzy":
            if rapidfuzz_process is None:
                raise RuntimeError("rapidfuzz is required for fallback retrieval")
            matches = rapidfuzz_process.extract(
                query,
                [doc["text"] for doc in self._documents],
                limit=top_k,
            )
            results: List[Dict[str, object]] = []
            for _, score, idx in matches:
                doc = self._documents[idx]
                results.append(
                    {
                        "table": doc.get("table"),
                        "url": doc.get("url"),
                        "text": doc.get("text"),
                        "score": float(score),
                    }
                )
            return results

        if self._index is None or self._dimension is None:
            raise RuntimeError("Embedding index is not initialized")

        model = self._load_model()
        query_embedding = model.encode(
            [query],
            convert_to_numpy=True,
            normalize_embeddings=True,
            show_progress_bar=False,
        ).astype(np.float32)

        scores, indices = self._index.search(query_embedding, top_k)
        results: List[Dict[str, object]] = []
        for score, idx in zip(scores[0], indices[0]):
            if idx < 0 or idx >= len(self._documents):
                continue
            doc = self._documents[idx]
            results.append(
                {
                    "table": doc.get("table"),
                    "url": doc.get("url"),
                    "text": doc.get("text"),
                    "score": float(score),
                }
            )
        return results

    def clear_cache(self) -> None:
        """Remove cached embeddings (primarily for testing)."""

        if self._metadata_path.exists():
            self._metadata_path.unlink()
        if self._index_path.exists():
            self._index_path.unlink()
        self._index = None
        self._documents = []
        self._dimension = None
        self._mode = "uninitialized"
        logger.info("Cleared RAG embeddings cache.")
