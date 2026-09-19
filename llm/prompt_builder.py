"""
llm/prompt_builder.py
--------------------
LLM Prompt Builder for Raven Phase 9 AST Context Compression.

Constructs structured LLM prompts from compressed code chunks, categorizing them
into high-risk (full source), medium-risk (signature + head), and low-risk (omitted)
tiers while preserving original line number references.
"""

from __future__ import annotations

from typing import List
from core.models import CompressedChunk


class PromptBuilder:
    """
    Constructs security analysis prompts for LLMs using AST-compressed code chunks.
    """

    PRIORITY_NAMES = {
        "main", "app", "create_app", "configure", "setup",
        "run", "start", "index", "handle_request"
    }

    def build_from_chunks(
        self,
        file_path: str,
        chunks: List[CompressedChunk],
        rag_chunks: List[str] | None = None,
        compression_ratio: float = 1.0
    ) -> str:
        """
        Builds a structured LLM prompt from compressed code chunks.
        Categorizes chunks into Tier 1 (Full), Tier 2 (Signatures), and Tier 3 (Omitted).
        """
        import_chunks: List[CompressedChunk] = []
        tier1_chunks: List[CompressedChunk] = []
        tier2_chunks: List[CompressedChunk] = []
        tier3_count = 0

        for chunk in chunks:
            # Imports are handled in a dedicated section
            if chunk.chunk_type == "import_block":
                import_chunks.append(chunk)
                continue

            # Always-include check
            name_lower = chunk.name.lower()
            always_include = (
                chunk.chunk_type == "global_assignment" or
                any(pname in name_lower for pname in self.PRIORITY_NAMES) or
                "hardcoded_string" in chunk.risk_reasons
            )

            if always_include or chunk.risk_score >= 0.40:
                tier1_chunks.append(chunk)
            elif 0.15 <= chunk.risk_score < 0.40:
                tier2_chunks.append(chunk)
            else:
                tier3_count += 1

        # Sort Tier 1 and Tier 2 by risk_score descending
        tier1_chunks.sort(key=lambda c: c.risk_score, reverse=True)
        tier2_chunks.sort(key=lambda c: c.risk_score, reverse=True)

        prompt_parts: List[str] = []

        # System Context Header
        prompt_parts.append(
            "You are RAVEN — an autonomous AI security auditor and penetration tester.\n"
            "Analyze the following code for exploitable security vulnerabilities (SQLi, XSS, CmdInj, SSTI, LFI, SSRF, Hardcoded Secrets, Auth Bypass).\n"
        )

        # Target File Metadata
        prompt_parts.append(
            "[TARGET FILE]\n"
            f"Path: {file_path}\n"
            f"Note: File compressed {compression_ratio:.1f}x — showing {len(tier1_chunks)} high-risk functions in full, "
            f"{len(tier2_chunks)} medium-risk functions as signatures only, {tier3_count} low-risk functions omitted.\n"
        )

        # Imports & Dependencies
        if import_chunks:
            prompt_parts.append("[IMPORTS & DEPENDENCIES]")
            for imp in import_chunks:
                prompt_parts.append(imp.source)
            prompt_parts.append("")

        # High-Risk Code Units (Tier 1)
        if tier1_chunks:
            prompt_parts.append("[HIGH-RISK CODE UNITS — ANALYZE THOROUGHLY]")
            for chunk in tier1_chunks:
                reasons_str = ", ".join(chunk.risk_reasons) if chunk.risk_reasons else "manual_review"
                prompt_parts.append(
                    f"--- {chunk.chunk_type}: {chunk.name} (lines {chunk.line_start}–{chunk.line_end}) ---\n"
                    f"Risk signals: {reasons_str}\n"
                    f"{chunk.source}\n"
                )

        # Medium-Risk Code Signatures (Tier 2)
        if tier2_chunks:
            prompt_parts.append("[MEDIUM-RISK CODE SIGNATURES — CHECK FOR PATTERNS]")
            for chunk in tier2_chunks:
                source_lines = chunk.source.splitlines()
                first_3 = "\n".join(source_lines[:3])
                omitted_lines = max(len(source_lines) - 3, 0)
                prompt_parts.append(
                    f"--- {chunk.chunk_type}: {chunk.name} (line {chunk.line_start}) ---\n"
                    f"{first_3}\n"
                    f"# [body compressed — {omitted_lines} lines omitted]\n"
                )

        # RAG Context
        if rag_chunks:
            prompt_parts.append("[RAG SECURITY CONTEXT]")
            for rchunk in rag_chunks[:3]:
                prompt_parts.append(f"---\n{rchunk}")
            prompt_parts.append("")

        # Analysis Instructions
        prompt_parts.append(
            "[ANALYSIS INSTRUCTIONS]\n"
            "Identify all vulnerabilities present in the code above.\n"
            "For each finding, provide: vulnerability_type, severity, line_number, parameter/variable, evidence, and remediation.\n"
            "IMPORTANT: All line number references in your findings must use the original line numbers shown above each code unit, NOT sequential numbers from this prompt."
        )

        return "\n".join(prompt_parts)

    def build(
        self,
        file_path: str,
        raw_content: str,
        rag_chunks: List[str] | None = None
    ) -> str:
        """
        Legacy prompt builder sending full raw file content (backward compatibility).
        """
        prompt_parts: List[str] = [
            "You are RAVEN — an autonomous AI security auditor.\n",
            f"[TARGET FILE]\nPath: {file_path}\n",
            f"[FILE CONTENTS]\n{raw_content}\n"
        ]

        if rag_chunks:
            prompt_parts.append("[RAG SECURITY CONTEXT]")
            for rchunk in rag_chunks[:3]:
                prompt_parts.append(f"---\n{rchunk}")
            prompt_parts.append("")

        prompt_parts.append(
            "[ANALYSIS INSTRUCTIONS]\n"
            "Identify all vulnerabilities present in the code above.\n"
            "For each finding, provide: vulnerability_type, severity, line_number, parameter/variable, evidence, and remediation."
        )

        return "\n".join(prompt_parts)
