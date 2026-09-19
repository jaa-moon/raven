"""
engine_models/coverage.py
-------------------------
Assessment coverage tracking model for Raven adaptive security assessment.

The system must never imply complete security coverage. Coverage items
explicitly state what was assessed, what was skipped, what was blocked,
and what was out of scope.
"""

from __future__ import annotations

from typing import List, Literal, Optional

from pydantic import BaseModel, Field


class CoverageItem(BaseModel):
    """
    A single entry in the assessment coverage report.

    Coverage items map attack surfaces and capabilities to their assessment
    status. The final report uses these to honestly communicate what was
    and was not tested.
    """

    surface: str = ""  # e.g., "SQL injection on /api/users", "JWT validation", "Container privileges"
    component_id: Optional[str] = None

    status: Literal[
        "tested",
        "partial",
        "not_assessed",
        "out_of_scope",
        "not_applicable",
        "blocked",
        "skipped_budget",
    ] = "not_assessed"

    reason: str = ""  # Why this status — especially important for non-tested items

    tools_used: List[str] = Field(default_factory=list)
    capabilities_used: List[str] = Field(default_factory=list)
    findings_count: int = 0

    @property
    def was_tested(self) -> bool:
        """True if some testing was performed on this surface."""
        return self.status in ("tested", "partial")

    @property
    def is_gap(self) -> bool:
        """True if this represents an untested area that should be highlighted."""
        return self.status in ("not_assessed", "blocked", "skipped_budget")
