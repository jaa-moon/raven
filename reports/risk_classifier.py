"""
reports/risk_classifier.py
--------------------------
Calculates CVSS-inspired risk score (0.0 to 10.0) and assigns qualitative risk labels.
"""

from __future__ import annotations

from typing import List, Tuple
from reports.models import AgentFinding, AttackChain


class RiskClassifier:
    """
    Calculates overall scan risk metrics.
    """

    @staticmethod
    def calculate_score(findings: List[AgentFinding], chains: List[AttackChain]) -> Tuple[float, str]:
        """
        Compute numeric score 0.0 - 10.0 and assign label (Critical, High, Medium, Low, Clean).
        """
        if not findings and not chains:
            return 0.0, "Clean"

        weights = {
            "Critical": 4.0,
            "High": 2.5,
            "Medium": 1.0,
            "Low": 0.4,
            "Info": 0.0
        }

        total_weight = 0.0
        for f in findings:
            total_weight += weights.get(f.severity, 0.5)

        # Chain multiplier
        for c in chains:
            total_weight += 3.0 if c.severity == "Critical" else 1.5

        # Normalize score onto 0.0 - 10.0 scale
        raw_score = min(10.0, round(total_weight, 1))

        if raw_score >= 8.0:
            label = "Critical"
        elif raw_score >= 5.5:
            label = "High"
        elif raw_score >= 3.0:
            label = "Medium"
        elif raw_score > 0.0:
            label = "Low"
        else:
            label = "Clean"

        return raw_score, label
