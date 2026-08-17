"""
rag/embeddings.py
-----------------
Singleton wrapper around sentence-transformers.

Design rationale
----------------
Loading the embedding model takes ~1-2 seconds and downloads ~22MB on first use.
By using a module-level singleton, we ensure the model is loaded at most once per
Raven process, even if multiple components call encode() during a scan.

Model choice: all-MiniLM-L6-v2
- 22MB on disk
- CPU-friendly (no GPU required for embedding 500-char chunks)
- 384-dimensional output — excellent quality/speed trade-off for semantic search
- Standard choice in production RAG systems for local deployments
"""

from __future__ import annotations

import numpy as np
from typing import Union, List

# Lazy import guard: we only import sentence_transformers when first needed.
# This avoids a slow import when --rules is used without --analyze.
_model = None
MODEL_NAME = "all-MiniLM-L6-v2"


def _get_model():
    """Load the embedding model on first call and cache it."""
    global _model
    if _model is None:
        from sentence_transformers import SentenceTransformer
        _model = SentenceTransformer(MODEL_NAME)
    return _model


class EmbeddingModel:
    """
    Thin wrapper around sentence-transformers for generating text embeddings.

    Usage:
        model = EmbeddingModel()
        vector = model.encode("SQL Injection in Flask")
    """

    def encode(self, text: Union[str, List[str]]) -> np.ndarray:
        """
        Encode one or more text strings into embedding vectors.

        Args:
            text: A single string or a list of strings to embed.

        Returns:
            numpy array of shape (embedding_dim,) for a single string,
            or (n, embedding_dim) for a list of strings.
        """
        model = _get_model()
        return model.encode(text, convert_to_numpy=True, show_progress_bar=False)
