"""
rag/retriever.py
----------------
Loads the FAISS index and retrieves the most relevant security knowledge
chunks for a given query string or stack profile.
"""

from __future__ import annotations

import json
from typing import Any, List, Optional

import numpy as np

from rag.embeddings import EmbeddingModel
from rag.ingest import (
    FAISS_INDEX_PATH,
    METADATA_PATH,
    TOOLS_INDEX_PATH,
    TOOLS_METADATA_PATH,
    KnowledgeIngestor,
)

import threading

# Module-level cache: keep the FAISS index and metadata in memory after first load
_index = None
_metadata: Optional[List[dict]] = None
_index_lock = threading.Lock()

_tools_index = None
_tools_metadata: Optional[List[dict]] = None
_tools_index_lock = threading.Lock()


def _ensure_index_loaded() -> tuple:
    """
    Lazily loads the FAISS index and metadata into memory.
    Triggers ingest() if the index doesn't exist yet.
    """
    global _index, _metadata
    import faiss

    if _index is None or _metadata is None:
        with _index_lock:
            if _index is None or _metadata is None:
                ingestor = KnowledgeIngestor()
                if not ingestor.is_index_built():
                    ingestor.ingest(verbose=False)

                _index = faiss.read_index(str(FAISS_INDEX_PATH))
                _metadata = json.loads(METADATA_PATH.read_text(encoding="utf-8"))

    return _index, _metadata


def _ensure_tools_index_loaded() -> tuple:
    """
    Lazily loads the Tools FAISS index and metadata into memory.
    Triggers ingest_tools() if the index doesn't exist yet.
    """
    global _tools_index, _tools_metadata
    import faiss

    if _tools_index is None or _tools_metadata is None:
        with _tools_index_lock:
            if _tools_index is None or _tools_metadata is None:
                ingestor = KnowledgeIngestor()
                if not ingestor.is_tools_index_built():
                    ingestor.ingest_tools(verbose=False)

                _tools_index = faiss.read_index(str(TOOLS_INDEX_PATH))
                _tools_metadata = json.loads(TOOLS_METADATA_PATH.read_text(encoding="utf-8"))

    return _tools_index, _tools_metadata


class SecurityRetriever:
    """
    Retrieves relevant security knowledge chunks from the FAISS index.

    Usage:
        retriever = SecurityRetriever()
        chunks = retriever.retrieve("Flask SQL injection vulnerability", top_k=3)
    """

    def __init__(self) -> None:
        self._embedder = EmbeddingModel()

    def retrieve(self, query: str, top_k: int = 3) -> List[str]:
        """
        Find the top-k most semantically relevant knowledge chunks for a query.
        """
        try:
            index, metadata = _ensure_index_loaded()

            # Embed the query
            query_vector = self._embedder.encode(query).astype(np.float32)
            query_vector = query_vector.reshape(1, -1)  # FAISS expects (1, dim)

            # Search the index
            distances, indices = index.search(query_vector, top_k)

            chunks: List[str] = []
            for idx in indices[0]:
                if idx == -1:  # FAISS returns -1 for empty slots
                    continue
                chunk_data = metadata[idx]
                source = chunk_data.get("source", "unknown")
                text = chunk_data.get("text", "")
                chunks.append(f"[Source: {source}]\n{text}")

            return chunks

        except Exception:
            return []

    def retrieve_for_stack(self, profile: Any, top_k: int = 3) -> List[str]:
        """
        Retrieve security knowledge chunks tailored to a specific ProjectProfile.
        """
        if profile is None:
            raise ValueError("ProjectProfile cannot be None for stack retrieval")

        language = getattr(profile, "language", "Unknown")
        framework = getattr(profile, "framework", "Unknown")
        deps = " ".join(getattr(profile, "dependencies", [])[:5])

        query = f"{language} {framework} pentest vulnerability attack vector {deps}".strip()
        return self.retrieve(query, top_k=top_k)


class ToolRetriever:
    """
    Retrieves relevant MCP tool descriptions from the Tools FAISS index.
    """

    def __init__(self) -> None:
        self._embedder = EmbeddingModel()

    def retrieve_for_context(self, query: str, top_k: int = 3) -> List[str]:
        """
        Find the top-k most semantically relevant tool descriptions for a query.
        """
        try:
            index, metadata = _ensure_tools_index_loaded()

            query_vector = self._embedder.encode(query).astype(np.float32)
            query_vector = query_vector.reshape(1, -1)

            distances, indices = index.search(query_vector, top_k)

            chunks: List[str] = []
            for idx in indices[0]:
                if idx == -1:
                    continue
                chunk_data = metadata[idx]
                source = chunk_data.get("source", "unknown")
                text = chunk_data.get("text", "")
                chunks.append(f"[Tool Docs: {source}]\n{text}")

            return chunks

        except Exception:
            return []
