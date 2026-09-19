"""
engine_models/validation.py
---------------------------
Validation result model for Raven adaptive security assessment.

Links findings to their validation outcomes, recording what was tested,
what method was used, and whether the finding was confirmed.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import List, Optional

from pydantic import BaseModel, Field

from engine_models.findings import ValidationStatus


class ValidationResult(BaseModel):
    """
    Outcome of validating a candidate finding.

    The validation engine processes each candidate finding and produces
    a ValidationResult recording the method, evidence, and conclusion.
    """

    validation_id: str = Field(default_factory=lambda: f"VAL-{uuid.uuid4().hex[:8]}")
    finding_id: str = ""

    status: ValidationStatus = ValidationStatus.PENDING

    # What validation method was used
    method: str = ""  # e.g., "reproduction", "differential_analysis", "manual_review"
    description: str = ""

    # Evidence from validation
    evidence_ids: List[str] = Field(default_factory=list)
    action_ids: List[str] = Field(default_factory=list)

    # Validation reasoning
    reasoning: str = ""
    alternative_explanations: List[str] = Field(default_factory=list)

    # Confidence adjustment
    confidence_before: str = "Low"
    confidence_after: str = "Low"

    # Timestamps
    started_at: str = Field(default_factory=lambda: datetime.now().isoformat())
    completed_at: Optional[str] = None

    def complete(self, status: ValidationStatus, reasoning: str = "") -> None:
        """Mark the validation as complete with a final status."""
        self.status = status
        self.reasoning = reasoning
        self.completed_at = datetime.now().isoformat()
