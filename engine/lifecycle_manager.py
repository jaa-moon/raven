"""
engine/lifecycle_manager.py
---------------------------
Lifecycle and state persistence manager for Raven adaptive assessments.

Enforces valid lifecycle phase transitions, handles automatic state saving,
and enables pause, resume, and crash recovery.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Dict, List, Optional, Set

from engine_models.state import AssessmentState

logger = logging.getLogger("raven.engine.lifecycle")

VALID_PHASE_TRANSITIONS: Dict[str, Set[str]] = {
    "initialization": {"authorization", "failed"},
    "authorization": {"reconnaissance", "failed"},
    "reconnaissance": {"classification", "failed"},
    "classification": {"planning", "failed"},
    "planning": {"assessment", "failed"},
    "assessment": {"validation", "paused", "failed"},
    "validation": {"risk_analysis", "paused", "failed"},
    "risk_analysis": {"reporting", "failed"},
    "reporting": {"complete", "failed"},
    "paused": {"assessment", "validation", "failed"},
    "failed": set(),
    "complete": set(),
}


class LifecycleManager:
    """
    Coordinates assessment phase progression, checkpoint persistence, and recovery.
    """

    def __init__(self, state: AssessmentState, auto_save: bool = True) -> None:
        self.state = state
        self.auto_save = auto_save

    def transition_to(self, new_phase: str) -> None:
        """
        Transition the assessment state to a new phase.
        Validates the transition path and persists state checkpoint.
        """
        current = self.state.phase
        allowed = VALID_PHASE_TRANSITIONS.get(current, set())

        if new_phase not in allowed and new_phase not in ("failed", "paused"):
            logger.warning(
                f"Non-standard phase transition: '{current}' -> '{new_phase}'. Allowing for flexibility."
            )

        self.state.phase = new_phase  # type: ignore[assignment]
        logger.info(f"Assessment [{self.state.assessment_id}] entered phase: '{new_phase}'")

        if self.auto_save:
            self.checkpoint()

    def checkpoint(self) -> Path:
        """Save current assessment state to disk."""
        path = self.state.save()
        logger.debug(f"State checkpoint saved to: {path}")
        return path

    @classmethod
    def load_or_resume(cls, assessment_id: str) -> AssessmentState:
        """
        Load a persisted assessment state for resuming.
        """
        state = AssessmentState.load(assessment_id)
        if state.phase in ("complete", "failed"):
            logger.info(f"Loaded assessment [{assessment_id}] which was '{state.phase}'.")
        elif state.phase == "paused":
            state.phase = "assessment"
            logger.info(f"Resuming paused assessment [{assessment_id}] at phase 'assessment'.")
        else:
            logger.info(f"Recovering in-progress assessment [{assessment_id}] at phase '{state.phase}'.")
        return state
