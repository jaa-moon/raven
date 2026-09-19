"""
engine_models/report.py
-----------------------
Universal pentest report model for Raven adaptive security assessment.

Clear separation between confirmed findings, inconclusive observations,
coverage tracking, limitations, and methodology documentation.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

from engine_models.coverage import CoverageItem
from engine_models.findings import Finding
from engine_models.risk import AttackPath, RiskScore
from engine_models.target import Target


class PentestReport(BaseModel):
    """
    Complete assessment report with honest, evidence-backed structure.

    The report clearly separates confirmed findings from inconclusive
    observations, documents assessment coverage, and lists limitations.
    It never implies completeness or zero false positives.
    """

    report_id: str = Field(default_factory=lambda: f"RPT-{uuid.uuid4().hex[:12]}")
    assessment_id: str = ""

    # Target summary
    target: Optional[Target] = None
    generated_at: str = Field(default_factory=lambda: datetime.now().isoformat())
    duration_seconds: float = 0.0

    # Findings — clearly separated by validation status
    confirmed_findings: List[Finding] = Field(default_factory=list)
    inconclusive_findings: List[Finding] = Field(default_factory=list)

    # Risk assessment
    risk_score: float = 0.0
    risk_label: str = "Clean"
    risk_detail: Optional[RiskScore] = None

    # Coverage and transparency
    coverage: List[CoverageItem] = Field(default_factory=list)

    # Assessment metrics
    total_requests_made: int = 0
    total_assets_discovered: int = 0
    total_tools_used: List[str] = Field(default_factory=list)
    total_capabilities_used: List[str] = Field(default_factory=list)

    # Narrative sections
    executive_summary: str = ""
    target_summary: str = ""
    methodology_summary: str = ""

    # Correlated attack paths
    attack_paths: List[AttackPath] = Field(default_factory=list)

    # Honest disclosure
    limitations: List[str] = Field(default_factory=list)
    not_assessed: List[str] = Field(default_factory=list)

    # Actionable output
    remediation_plan: List[str] = Field(default_factory=list)

    @property
    def total_confirmed(self) -> int:
        return len(self.confirmed_findings)

    @property
    def total_inconclusive(self) -> int:
        return len(self.inconclusive_findings)

    @property
    def severity_breakdown(self) -> Dict[str, int]:
        """Count confirmed findings by severity."""
        counts: Dict[str, int] = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
        for f in self.confirmed_findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        return counts

    @property
    def has_critical_findings(self) -> bool:
        return any(f.severity == "Critical" for f in self.confirmed_findings)

    @property
    def coverage_percentage(self) -> float:
        """Percentage of coverage items that were tested."""
        if not self.coverage:
            return 0.0
        tested = sum(1 for c in self.coverage if c.was_tested)
        return round((tested / len(self.coverage)) * 100, 1)
