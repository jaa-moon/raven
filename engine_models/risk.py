"""
engine_models/risk.py
---------------------
Risk correlation and attack path models for Raven adaptive security assessment.

Correlates findings across components and agents to identify multi-step
attack paths. Distinguishes confirmed paths (evidence-backed) from
plausible paths (hypothetical relationships).
"""

from __future__ import annotations

import uuid
from typing import List, Literal, Optional

from pydantic import BaseModel, Field


class AttackPathStep(BaseModel):
    """A single step in a multi-finding attack path."""

    step_number: int = 0
    finding_id: str = ""
    description: str = ""
    asset_id: str = ""
    technique: str = ""


class AttackPath(BaseModel):
    """
    A correlated multi-step attack path across findings and components.

    Attack paths represent the real-world exploitation potential when
    multiple vulnerabilities are chained together. Only evidence-backed
    relationships should be marked as confirmed.
    """

    path_id: str = Field(default_factory=lambda: f"ATK-{uuid.uuid4().hex[:8]}")
    assessment_id: str = ""

    name: str = ""
    description: str = ""

    steps: List[AttackPathStep] = Field(default_factory=list)
    finding_ids: List[str] = Field(default_factory=list)

    severity: Literal["Critical", "High", "Medium"] = "High"
    confidence: Literal["confirmed", "plausible", "hypothetical"] = "plausible"

    combined_impact: str = ""
    time_to_exploit: str = ""

    # Evidence linking the steps together
    evidence_ids: List[str] = Field(default_factory=list)
    component_ids: List[str] = Field(default_factory=list)

    @property
    def is_confirmed(self) -> bool:
        """True if the attack path is backed by evidence."""
        return self.confidence == "confirmed"

    @property
    def step_count(self) -> int:
        return len(self.steps)


class RiskScore(BaseModel):
    """Computed risk assessment for the overall target."""

    score: float = 0.0  # 0.0 - 10.0
    label: Literal["Critical", "High", "Medium", "Low", "Clean"] = "Clean"

    confirmed_finding_count: int = 0
    inconclusive_finding_count: int = 0
    attack_path_count: int = 0

    severity_breakdown: dict = Field(default_factory=lambda: {
        "Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0
    })

    methodology: str = "CVSS-inspired weighted scoring"
