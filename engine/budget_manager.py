"""
engine/budget_manager.py
------------------------
Execution budget manager for Raven adaptive security assessment.

Enforces execution bounds across tool invocations, HTTP/network requests,
runtime seconds, and retry counts to ensure assessments terminate predictably.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Dict, Literal, Optional

from engine_models.state import AssessmentState


@dataclass
class BudgetLimits:
    """Configurable limits for an assessment run."""

    max_tool_calls: int = 100
    max_requests: int = 500
    max_runtime_seconds: float = 600.0
    max_retries_per_action: int = 3
    max_same_action: int = 3
    max_crawl_depth: int = 3

    @classmethod
    def for_depth(cls, depth: Literal["quick", "standard", "deep"] | str) -> BudgetLimits:
        """Standard presets for assessment depth."""
        d = str(depth).lower()
        if d == "quick":
            return cls(
                max_tool_calls=30,
                max_requests=150,
                max_runtime_seconds=300.0,
                max_retries_per_action=2,
                max_same_action=2,
                max_crawl_depth=2,
            )
        elif d == "deep":
            return cls(
                max_tool_calls=200,
                max_requests=2000,
                max_runtime_seconds=3600.0,
                max_retries_per_action=4,
                max_same_action=4,
                max_crawl_depth=5,
            )
        else:  # standard
            return cls(
                max_tool_calls=80,
                max_requests=500,
                max_runtime_seconds=900.0,
                max_retries_per_action=3,
                max_same_action=3,
                max_crawl_depth=3,
            )


class BudgetManager:
    """
    Tracks and enforces resource consumption during an assessment.
    """

    def __init__(self, limits: Optional[BudgetLimits] = None) -> None:
        self.limits: BudgetLimits = limits or BudgetLimits()
        self.tool_calls: int = 0
        self.requests_made: int = 0
        self.start_time: float = time.time()
        self._action_retries: Dict[str, int] = {}
        self._action_counts: Dict[str, int] = {}

    @property
    def elapsed_seconds(self) -> float:
        return time.time() - self.start_time

    def can_afford(self, tool_calls: int = 1, requests: int = 1, calls: Optional[int] = None) -> bool:
        """Check if requested operations fit within remaining budget."""
        effective_calls = calls if calls is not None else tool_calls
        if self.tool_calls + effective_calls > self.limits.max_tool_calls:
            return False
        if self.requests_made + requests > self.limits.max_requests:
            return False
        if self.elapsed_seconds >= self.limits.max_runtime_seconds:
            return False
        return True

    def consume(self, tool_calls: int = 1, requests: int = 0) -> None:
        """Record consumption of budget units."""
        self.tool_calls += tool_calls
        self.requests_made += requests

    def record_retry(self, action_id: str) -> bool:
        """
        Increment and check retries for a given action.
        Returns True if retry is permitted, False if limit exceeded.
        """
        current = self._action_retries.get(action_id, 0) + 1
        self._action_retries[action_id] = current
        return current <= self.limits.max_retries_per_action

    def check_repeated_action(self, action_key: str) -> bool:
        """
        Record and check whether an identical action has exceeded max_same_action limit.
        Returns True if action is allowed, False if repeated action limit exceeded.
        """
        count = self._action_counts.get(action_key, 0) + 1
        self._action_counts[action_key] = count
        return count <= self.limits.max_same_action

    def is_exhausted(self) -> bool:
        """True if any budget dimension has reached its ceiling."""
        return (
            self.tool_calls >= self.limits.max_tool_calls
            or self.requests_made >= self.limits.max_requests
            or self.elapsed_seconds >= self.limits.max_runtime_seconds
        )

    def is_soft_exhausted(self) -> bool:
        """
        True if any budget dimension has reached 90% of its ceiling.
        Used by agents to gracefully wrap up without starting new hypotheses.
        """
        return (
            self.tool_calls >= (self.limits.max_tool_calls * 0.90)
            or self.requests_made >= (self.limits.max_requests * 0.90)
            or self.elapsed_seconds >= (self.limits.max_runtime_seconds * 0.90)
        )

    def remaining_calls(self) -> int:
        return max(0, self.limits.max_tool_calls - self.tool_calls)

    def remaining_requests(self) -> int:
        return max(0, self.limits.max_requests - self.requests_made)

    def remaining_seconds(self) -> float:
        return max(0.0, self.limits.max_runtime_seconds - self.elapsed_seconds)

    def sync_to_state(self, state: AssessmentState) -> None:
        """Persist budget usage into AssessmentState counters."""
        state.total_tool_calls = self.tool_calls
        state.total_requests_made = self.requests_made
        state.elapsed_seconds = round(self.elapsed_seconds, 2)
