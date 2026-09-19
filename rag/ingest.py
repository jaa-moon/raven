"""
rag/ingest.py
-------------
Loads all markdown knowledge files, chunks them, generates embeddings, and
stores a FAISS index on disk for later retrieval.

Design rationale
----------------
Chunking strategy: 500-character chunks with 50-character overlap.
- Small enough to keep each chunk semantically focused on one topic.
- 50-char overlap prevents losing context across chunk boundaries.
- Simple character-based chunking is sufficient for structured markdown docs.

Index storage: stored in rag/index/ as two files:
  - faiss.index  : the FAISS flat L2 index (vector data)
  - metadata.json: maps each vector ID to its source file path + chunk text

Auto-ingest: the retriever calls is_index_built() and if False, triggers
ingest() automatically — so users never need to run a manual ingest step.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import List, Tuple

import numpy as np

from rag.embeddings import EmbeddingModel

# Paths
_HERE = Path(__file__).parent
KNOWLEDGE_DIR = _HERE.parent / "knowledge"
INDEX_DIR = _HERE / "index"
FAISS_INDEX_PATH = INDEX_DIR / "faiss.index"
METADATA_PATH = INDEX_DIR / "metadata.json"
TOOLS_INDEX_PATH = INDEX_DIR / "tools_index.faiss"
TOOLS_METADATA_PATH = INDEX_DIR / "tools_metadata.json"

# Chunking parameters
CHUNK_SIZE = 500      # characters per chunk
CHUNK_OVERLAP = 50    # overlap between consecutive chunks


def _chunk_text(text: str, chunk_size: int = CHUNK_SIZE, overlap: int = CHUNK_OVERLAP) -> List[str]:
    """
    Split text into overlapping fixed-size character chunks.

    Args:
        text:       The full document text.
        chunk_size: Maximum characters per chunk.
        overlap:    Number of characters shared between consecutive chunks.

    Returns:
        List of text chunks.
    """
    chunks: List[str] = []
    start = 0
    while start < len(text):
        end = min(start + chunk_size, len(text))
        chunk = text[start:end].strip()
        if chunk:
            chunks.append(chunk)
        start += chunk_size - overlap
    return chunks


def _load_knowledge_files() -> List[Tuple[str, str]]:
    """
    Recursively loads all .md files from the knowledge directory.

    Returns:
        List of (source_path_str, full_text) tuples.
    """
    docs: List[Tuple[str, str]] = []
    for md_file in sorted(KNOWLEDGE_DIR.rglob("*.md")):
        try:
            text = md_file.read_text(encoding="utf-8", errors="ignore").strip()
            if text:
                # Use a relative path label for display in retrieval
                rel = md_file.relative_to(KNOWLEDGE_DIR).as_posix()
                docs.append((rel, text))
        except Exception:
            continue
    return docs


def _load_tools_files() -> List[Tuple[str, str]]:
    """
    Recursively loads all .md files from the knowledge/tools directory.
    """
    docs: List[Tuple[str, str]] = []
    tools_dir = KNOWLEDGE_DIR / "tools"
    if not tools_dir.exists():
        return docs
    for md_file in sorted(tools_dir.rglob("*.md")):
        try:
            text = md_file.read_text(encoding="utf-8", errors="ignore").strip()
            if text:
                rel = md_file.relative_to(KNOWLEDGE_DIR).as_posix()
                docs.append((rel, text))
        except Exception:
            continue
    return docs


class KnowledgeIngestor:
    """
    Builds and saves a FAISS vector index from the security knowledge base.

    Usage:
        ingestor = KnowledgeIngestor()
        if not ingestor.is_index_built():
            ingestor.ingest()
    """

    def __init__(self) -> None:
        self._embedder = EmbeddingModel()

    def is_index_built(self) -> bool:
        """Returns True if the FAISS index and metadata files already exist."""
        return FAISS_INDEX_PATH.exists() and METADATA_PATH.exists()

    def is_tools_index_built(self) -> bool:
        """Returns True if the tools FAISS index and metadata files already exist."""
        return TOOLS_INDEX_PATH.exists() and TOOLS_METADATA_PATH.exists()

    def ingest(self, verbose: bool = False) -> int:
        """
        Loads all knowledge files, chunks and embeds them, and saves a FAISS index.

        Args:
            verbose: If True, prints progress to stdout.

        Returns:
            Total number of chunks indexed.
        """
        import faiss  # Import here so the rest of Raven works even if faiss isn't installed

        INDEX_DIR.mkdir(parents=True, exist_ok=True)

        # ── Load all markdown documents ───────────────────────────────────────
        docs = _load_knowledge_files()
        if not docs:
            raise RuntimeError(f"No knowledge files found in {KNOWLEDGE_DIR}")

        if verbose:
            print(f"Loaded {len(docs)} knowledge documents.")

        # ── Chunk all documents ───────────────────────────────────────────────
        all_chunks: List[str] = []
        chunk_metadata: List[dict] = []

        for source_path, text in docs:
            chunks = _chunk_text(text)
            for chunk in chunks:
                all_chunks.append(chunk)
                chunk_metadata.append({
                    "source": source_path,
                    "text": chunk,
                })

        if verbose:
            print(f"Generated {len(all_chunks)} chunks from {len(docs)} documents.")

        # ── Generate embeddings ───────────────────────────────────────────────
        if verbose:
            print("Generating embeddings (this may take a moment on first run)...")

        vectors = self._embedder.encode(all_chunks)  # shape: (n_chunks, 384)
        vectors = vectors.astype(np.float32)

        # ── Build FAISS index ─────────────────────────────────────────────────
        dim = vectors.shape[1]
        index = faiss.IndexFlatL2(dim)   # Exact L2 distance search — no approximation
        index.add(vectors)

        # ── Save index and metadata ───────────────────────────────────────────
        faiss.write_index(index, str(FAISS_INDEX_PATH))
        METADATA_PATH.write_text(
            json.dumps(chunk_metadata, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )

        if verbose:
            print(f"FAISS index saved to {FAISS_INDEX_PATH} ({len(all_chunks)} vectors).")

        return len(all_chunks)

    def ingest_tools(self, verbose: bool = False) -> int:
        """
        Loads all tool knowledge files, chunks and embeds them, and saves a separate tools FAISS index.
        """
        import faiss

        INDEX_DIR.mkdir(parents=True, exist_ok=True)

        docs = _load_tools_files()
        if not docs:
            if verbose:
                print(f"No tool knowledge files found in {KNOWLEDGE_DIR / 'tools'}")
            return 0

        all_chunks: List[str] = []
        chunk_metadata: List[dict] = []

        for source_path, text in docs:
            chunks = _chunk_text(text)
            for chunk in chunks:
                all_chunks.append(chunk)
                chunk_metadata.append({
                    "source": source_path,
                    "text": chunk,
                })

        vectors = self._embedder.encode(all_chunks)
        vectors = vectors.astype(np.float32)

        dim = vectors.shape[1]
        index = faiss.IndexFlatL2(dim)
        index.add(vectors)

        faiss.write_index(index, str(TOOLS_INDEX_PATH))
        TOOLS_METADATA_PATH.write_text(
            json.dumps(chunk_metadata, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )

        return len(all_chunks)
