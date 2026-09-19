"""
engine_models/results.py
------------------------
Standardized tool result model for Raven adaptive security assessment.

Every tool — HTTP probers, port scanners, static analyzers, cloud API
clients, binary inspectors — must return results through this contract.
Agents never depend on raw, unstructured tool output.
"""

from __future__ import annotations

from typing import Any, Dict, List, Literal

from pydantic import BaseModel, Field


class NormalizedToolResult(BaseModel):
    """
    Standard result contract for all tool invocations.

    The result_processor normalizes tool-specific outputs (HTTP responses,
    Nmap output, static analysis findings, cloud API responses, etc.)
    into this common structure.

    Named NormalizedToolResult to avoid conflict with the existing
    gateway.ToolResult dataclass which is preserved for backward compat.
    """

    action_id: str = ""
    tool_name: str = ""
    target: str = ""

    status: Literal[
        "success",
        "partial_success",
        "timeout",
        "error",
        "out_of_scope",
        "invalid_args",
        "tool_unavailable",
        "permission_denied",
        "sandbox_failure",
        "target_unreachable",
        "rate_limited",
    ] = "success"

    duration_ms: float = 0.0

    # Primary result data (tool-specific, normalized to dict)
    data: Dict[str, Any] = Field(default_factory=dict)

    # Structured observations extracted from the result
    observations: List[str] = Field(default_factory=list)

    # Evidence items for finding substantiation
    evidence: List[str] = Field(default_factory=list)

    # Serialized artifacts (file paths, screenshots, etc.)
    artifacts: List[str] = Field(default_factory=list)

    # Newly discovered assets from this tool execution
    discovered_assets: List[Dict[str, Any]] = Field(default_factory=list)

    # Relationships between discovered assets
    relationships: List[Dict[str, Any]] = Field(default_factory=list)

    # Errors and warnings
    errors: List[str] = Field(default_factory=list)
    warnings: List[str] = Field(default_factory=list)

    # Agent hints for next steps
    next_possible_actions: List[str] = Field(default_factory=list)

    # Overall confidence in the result quality
    confidence: str = "Low"  # High, Medium, Low

    @property
    def is_success(self) -> bool:
        """True if the tool completed without fatal errors."""
        return self.status in ("success", "partial_success")

    @property
    def is_error(self) -> bool:
        """True if the tool encountered a fatal error."""
        return self.status in ("error", "timeout", "tool_unavailable", "sandbox_failure")
