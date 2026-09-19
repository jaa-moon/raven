"""
engine/risk_engine.py
---------------------
Risk calculation and correlation engine for Raven adaptive security assessment.

Computes weighted CVSS-inspired risk scores, coordinates attack path identification,
and enforces honest coverage metrics.
"""

from __future__ import annotations

import logging
from typing import Dict, List, Tuple

from agents.risk_agent import RiskAgent
from engine.assessment_context import AssessmentContext
from engine.coverage_tracker import CoverageTracker
from engine_models.findings import Finding
from engine_models.risk import AttackPath, RiskScore

logger = logging.getLogger("raven.engine.risk")


class RiskEngine:
    """
    Synthesizes finding severities, attack paths, and coverage into actionable risk assessments.
    """

    SEVERITY_WEIGHTS = {
        "Critical": 10.0,
        "High": 7.5,
        "Medium": 4.5,
        "Low": 2.0,
        "Info": 0.5,
    }

    def __init__(self, context: AssessmentContext) -> None:
        self.context = context
        self.agent = RiskAgent(context)
        self.coverage_tracker = CoverageTracker(context)

    async def analyze(self) -> Tuple[RiskScore, List[AttackPath]]:
        """
        Execute full risk correlation, attack path identification, and coverage tracking.
        """
        ctx = self.context

        # 1. Identify attack paths
        attack_paths = await self.agent.identify_attack_paths()

        # 2. Track coverage
        self.coverage_tracker.track()

        # 3. Calculate RiskScore
        score_obj = self.calculate_score(ctx.state.confirmed_findings, attack_paths)
        score_obj.inconclusive_finding_count = len(ctx.state.inconclusive_findings)

        return score_obj, attack_paths

    @classmethod
    def calculate_score(
        cls,
        findings: List[Finding],
        attack_paths: List[AttackPath],
    ) -> RiskScore:
        """
        Compute weighted CVSS-inspired risk score based on confirmed findings and attack paths.
        """
        if not findings:
            return RiskScore(
                score=0.0,
                label="Clean",
                confirmed_finding_count=0,
                attack_path_count=len(attack_paths),
            )

        breakdown = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
        max_score = 0.0
        weighted_sum = 0.0

        for f in findings:
            sev = f.severity.capitalize() if f.severity else "Info"
            if sev not in breakdown:
                sev = "Info"
            breakdown[sev] += 1
            w = cls.SEVERITY_WEIGHTS.get(sev, 0.5)
            weighted_sum += w
            if f.cvss_score > max_score:
                max_score = f.cvss_score

        # Base score driven by highest finding, scaled slightly by volume
        calculated = min(10.0, max(max_score, weighted_sum / (1.0 + 0.3 * len(findings))))

        # If confirmed attack path exists, elevate risk score
        if any(p.is_confirmed for p in attack_paths):
            calculated = min(10.0, calculated + 1.0)

        calculated = round(calculated, 1)

        if calculated >= 9.0:
            label = "Critical"
        elif calculated >= 7.0:
            label = "High"
        elif calculated >= 4.0:
            label = "Medium"
        elif calculated > 0.0:
            label = "Low"
        else:
            label = "Clean"

        return RiskScore(
            score=calculated,
            label=label,  # type: ignore[arg-type]
            confirmed_finding_count=len(findings),
            attack_path_count=len(attack_paths),
            severity_breakdown=breakdown,
        )
