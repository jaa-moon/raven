"""
engine/hypothesis_manager.py
----------------------------
Hypothesis lifecycle manager for Raven adaptive security assessment.

Tracks, updates, and correlates security hypotheses from proposition through testing
to confirmation, rejection, or inconclusive outcome.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from engine_models.hypotheses import Hypothesis
from engine_models.state import AssessmentState

logger = logging.getLogger("raven.engine.hypotheses")


class HypothesisManager:
    """
    Coordinates hypothesis lifecycles and manages state hypothesis collections.
    """

    def __init__(self, state: AssessmentState) -> None:
        self.state = state

    def add_hypothesis(self, hypothesis: Hypothesis) -> Hypothesis:
        """Register a new hypothesis in assessment state."""
        self.state.hypotheses.append(hypothesis)
        logger.debug(f"Hypothesis registered: [{hypothesis.hypothesis_id}] {hypothesis.title}")
        return hypothesis

    def get_by_id(self, hypothesis_id: str) -> Optional[Hypothesis]:
        """Fetch hypothesis by ID."""
        for h in self.state.hypotheses:
            if h.hypothesis_id == hypothesis_id:
                return h
        return None

    def get_untested(self, capability_id: Optional[str] = None) -> List[Hypothesis]:
        """Retrieve all hypotheses that have not yet been conclusively resolved."""
        results = []
        for h in self.state.hypotheses:
            if h.is_testable:
                if capability_id is None or h.capability_id == capability_id:
                    results.append(h)
        # Return sorted by priority (highest first)
        return sorted(results, key=lambda x: x.priority, reverse=True)

    def start_testing(self, hypothesis_id: str, action_id: Optional[str] = None) -> None:
        """Mark hypothesis as currently under testing."""
        h = self.get_by_id(hypothesis_id)
        if h:
            h.status = "testing"
            if action_id and action_id not in h.action_ids:
                h.action_ids.append(action_id)

    def resolve(
        self,
        hypothesis_id: str,
        status: str,
        reason: str = "",
        finding_id: Optional[str] = None,
        evidence_ids: Optional[List[str]] = None,
    ) -> None:
        """Resolve hypothesis with outcome, reason, and optional finding reference."""
        h = self.get_by_id(hypothesis_id)
        if h:
            h.resolve(status, reason)
            if finding_id:
                h.finding_id = finding_id
            if evidence_ids:
                h.evidence_ids.extend(evidence_ids)
            logger.info(f"Hypothesis [{h.hypothesis_id}] resolved: {status} ({reason})")

    def all_hypotheses(self) -> List[Hypothesis]:
        """Return all tracked hypotheses."""
        return self.state.hypotheses
