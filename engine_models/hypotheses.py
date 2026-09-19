"""
engine_models/hypotheses.py
---------------------------
Hypothesis lifecycle model for Raven adaptive security assessment.

Agents formulate testable security hypotheses, execute tools to gather
evidence, and transition hypotheses through: proposed → testing →
confirmed / rejected / inconclusive.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import List, Literal, Optional

from pydantic import BaseModel, Field


class Hypothesis(BaseModel):
    """
    A testable security assumption about the target.

    Hypotheses drive the agent assessment loop. Each hypothesis specifies
    what vulnerability is suspected, what evidence would confirm it,
    and which tools should be used to test it.
    """

    hypothesis_id: str = Field(default_factory=lambda: f"HYP-{uuid.uuid4().hex[:8]}")
    capability_id: str = ""
    agent_name: str = ""

    # The hypothesis statement
    title: str = ""
    description: str = ""
    vulnerability_type: str = ""

    # What would confirm or reject this hypothesis
    confirmation_criteria: str = ""
    rejection_criteria: str = ""

    # Target asset(s) being tested
    target_asset_ids: List[str] = Field(default_factory=list)

    # Suggested tools and approach
    suggested_tools: List[str] = Field(default_factory=list)
    priority: int = 0  # Higher = more important

    # Lifecycle tracking
    status: Literal[
        "proposed",
        "testing",
        "confirmed",
        "rejected",
        "inconclusive",
        "skipped",
    ] = "proposed"

    # Linked evidence and findings
    action_ids: List[str] = Field(default_factory=list)  # AgentActions that tested this
    evidence_ids: List[str] = Field(default_factory=list)
    finding_id: Optional[str] = None  # Created finding, if any

    # Metadata
    reason: str = ""  # Why was it confirmed/rejected/skipped
    created_at: str = Field(default_factory=lambda: datetime.now().isoformat())
    resolved_at: Optional[str] = None

    def resolve(self, status: str, reason: str = "") -> None:
        """Transition hypothesis to a terminal state."""
        self.status = status  # type: ignore[assignment]
        self.reason = reason
        self.resolved_at = datetime.now().isoformat()

    @property
    def is_terminal(self) -> bool:
        """True if the hypothesis has reached a final state."""
        return self.status in ("confirmed", "rejected", "inconclusive", "skipped")

    @property
    def is_testable(self) -> bool:
        """True if the hypothesis can still be tested."""
        return self.status in ("proposed", "testing")
