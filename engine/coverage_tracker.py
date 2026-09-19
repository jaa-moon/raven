"""
engine/coverage_tracker.py
--------------------------
Assessment coverage tracker for Raven adaptive security assessment.

Ensures transparent, honest reporting of what was tested, what was skipped,
what was blocked by scope, and what remained unassessed.
"""

from __future__ import annotations

import logging
from typing import List

from engine.assessment_context import AssessmentContext
from engine_models.coverage import CoverageItem

logger = logging.getLogger("raven.engine.coverage")


class CoverageTracker:
    """
    Computes assessment coverage items and honest completeness metrics.
    """

    def __init__(self, context: AssessmentContext) -> None:
        self.context = context

    def track(self) -> List[CoverageItem]:
        """
        Synthesize coverage items for all planned tests and unassessed areas.
        """
        state = self.context.state
        coverage_items: List[CoverageItem] = []

        # 1. Planned tests that were executed
        for test_name in state.planned_tests:
            # Check if any tool failures occurred on this capability
            matching_failures = [
                f for f in state.tool_failures if f.get("tool_name") in test_name
            ]
            if matching_failures:
                coverage_items.append(
                    CoverageItem(
                        surface=test_name,
                        status="partial",
                        reason=f"Encountered {len(matching_failures)} tool errors during execution",
                    )
                )
            else:
                coverage_items.append(
                    CoverageItem(
                        surface=test_name,
                        status="tested",
                        reason="Assessed via specialized capability agent",
                    )
                )

        # 2. Capabilities that were not activated or excluded
        for item in state.not_assessed:
            parts = item.split(":", 1)
            cap_id = parts[0].strip()
            reason = parts[1].strip() if len(parts) > 1 else "Not activated for this target profile"

            status = "out_of_scope" if "scope" in reason.lower() or "exclude" in reason.lower() else "not_assessed"
            coverage_items.append(
                CoverageItem(
                    surface=f"Capability: {cap_id}",
                    status=status,
                    reason=reason,
                )
            )

        state.coverage = coverage_items
        return coverage_items
