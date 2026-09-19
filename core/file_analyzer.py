"""
core/file_analyzer.py
--------------------
Thread-safe static file analyzer for Raven Phase 9.

Reads target source files, applies AST Context Compression, constructs prompts
from high-risk code units, and coordinates with LLM providers for static analysis.
"""

from __future__ import annotations

import os
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any, Dict, List, Optional

from core.ast_compressor import ASTCompressor
from core.models import CompressionResult
from llm.prompt_builder import PromptBuilder
from providers.base import BaseProvider
from ui.console import console


class FileAnalyzer:
    """
    Orchestrates static source file scanning with AST Context Compression.
    """

    def __init__(
        self,
        provider: Optional[BaseProvider] = None,
        compressor: Optional[ASTCompressor] = None,
        rag_chunks: Optional[List[str]] = None,
    ) -> None:
        self.provider = provider
        self.compressor = compressor or ASTCompressor()
        self.rag_chunks = rag_chunks or []
        self.prompt_builder = PromptBuilder()
        self._compression_stats: List[CompressionResult] = []
        self._lock = threading.Lock()

    def analyze_file(self, file_path: str, language: str) -> Dict[str, Any]:
        """
        Reads, compresses, and analyzes a single source file.
        """
        path = Path(file_path).resolve()
        if not path.exists() or not path.is_file():
            return {"file_path": file_path, "error": "File does not exist"}

        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                raw_content = f.read()

            compression_result = self.compressor.compress(
                file_path=str(path),
                raw_content=raw_content,
                language=language
            )

            # Thread-safe stats collection
            with self._lock:
                self._compression_stats.append(compression_result)

            # Build prompt from compressed chunks
            prompt = self.prompt_builder.build_from_chunks(
                file_path=str(path),
                chunks=compression_result.chunks,
                rag_chunks=self.rag_chunks,
                compression_ratio=compression_result.compression_ratio
            )

            analysis_response = ""
            if self.provider and self.provider.is_available():
                try:
                    analysis_response = self.provider.analyze(
                        "You are a senior red-team security auditor performing static analysis on compressed code units.",
                        prompt
                    )
                except Exception as e:
                    console.print(f"[yellow]LLM static analysis failed for {path.name}: {e}[/]")

            return {
                "file_path": str(path),
                "language": language,
                "compression_result": compression_result,
                "prompt": prompt,
                "analysis": analysis_response
            }

        except Exception as e:
            console.print(f"[yellow]AST compression failed for {file_path}: {e} — using raw content fallback[/]")
            return {"file_path": file_path, "error": str(e)}

    def analyze_project(
        self,
        target_path: Path | str,
        language: str = "Python",
        max_workers: int = 16
    ) -> List[Dict[str, Any]]:
        """
        Scans all source code files in a project directory using multi-worker execution.
        """
        target = Path(target_path).resolve()
        if not target.exists() or not target.is_dir():
            return []

        # Find target source files based on language extension
        ext_map = {
            "python": [".py"],
            "javascript": [".js", ".jsx"],
            "typescript": [".ts", ".tsx"],
            "nodejs": [".js", ".ts"],
            "go": [".go"]
        }

        exts = ext_map.get(language.lower(), [".py", ".js", ".ts", ".go"])
        source_files: List[Path] = []

        for root, dirs, files in os.walk(target):
            # Skip hidden, virtualenv, and build directories
            dirs[:] = [d for d in dirs if not d.startswith(".") and d not in ("venv", "node_modules", "__pycache__", "dist", "build")]
            for file in files:
                p = Path(root) / file
                if p.suffix.lower() in exts and p.stat().st_size < 500_000:
                    source_files.append(p)

        if not source_files:
            return []

        results: List[Dict[str, Any]] = []

        # Run concurrent file compression and analysis
        with ThreadPoolExecutor(max_workers=min(max_workers, len(source_files))) as executor:
            future_to_file = {
                executor.submit(self.analyze_file, str(f), language): f
                for f in source_files
            }
            for future in as_completed(future_to_file):
                try:
                    res = future.result()
                    results.append(res)
                except Exception:
                    pass

        return results

    def compression_summary(self) -> Dict[str, Any]:
        """
        Calculates aggregate AST compression statistics across all analyzed files.
        """
        with self._lock:
            if not self._compression_stats:
                return {}

            total_original = sum(r.original_char_count for r in self._compression_stats)
            total_compressed = sum(r.compressed_char_count for r in self._compression_stats)
            fallbacks = sum(1 for r in self._compression_stats if r.fallback_used)

            overall_ratio = round(total_original / max(total_compressed, 1), 2)
            token_reduction_pct = round(
                (1 - total_compressed / max(total_original, 1)) * 100, 1
            )

            return {
                "files_compressed": len(self._compression_stats),
                "total_original_chars": total_original,
                "total_compressed_chars": total_compressed,
                "overall_ratio": overall_ratio,
                "estimated_token_reduction_pct": token_reduction_pct,
                "fallback_count": fallbacks,
            }
