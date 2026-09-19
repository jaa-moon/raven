"""
core/budget.py
--------------
Centralized resource budget. The gateway consults it before every execution;
the planner reads `status()` so it can prioritize *before* the budget is gone
instead of failing abruptly.
"""

from __future__ import annotations

import time
from typing import Callable, Dict, List

from pydantic import BaseModel


class BudgetLimits(BaseModel):
    max_tool_calls: int = 120
    max_seconds: float = 900.0
    max_iterations: int = 40        # adaptive-loop depth
    max_retries: int = 2            # per request
    max_llm_calls: int = 30
    max_expensive_ops: int = 6

    @classmethod
    def for_depth(cls, depth: str) -> "BudgetLimits":
        d = (depth or "standard").lower()
        if d == "quick":
            return cls(max_tool_calls=45, max_seconds=240, max_iterations=15,
                       max_retries=1, max_llm_calls=10, max_expensive_ops=2)
        if d == "deep":
            return cls(max_tool_calls=400, max_seconds=3600, max_iterations=200,
                       max_retries=3, max_llm_calls=80, max_expensive_ops=20)
        return cls()


class BudgetManager:
    CONSTRAINED = 0.75
    CRITICAL = 0.90

    def __init__(self, limits: BudgetLimits | None = None,
                 clock: Callable[[], float] = time.monotonic) -> None:
        self.limits = limits or BudgetLimits()
        self._clock = clock
        self._start = clock()
        self.tool_calls = 0
        self.llm_calls = 0
        self.expensive_ops = 0
        self.iterations = 0
        self._retries: Dict[str, int] = {}

    # -- accounting -------------------------------------------------------------

    @property
    def elapsed(self) -> float:
        return self._clock() - self._start

    def consume(self, tool_calls: int = 0, llm_calls: int = 0, expensive: int = 0) -> None:
        self.tool_calls += tool_calls
        self.llm_calls += llm_calls
        self.expensive_ops += expensive

    def next_iteration(self) -> None:
        self.iterations += 1

    def record_retry(self, key: str) -> bool:
        """True if another retry of *key* is still permitted."""
        n = self._retries.get(key, 0) + 1
        self._retries[key] = n
        return n <= self.limits.max_retries

    # -- queries ----------------------------------------------------------------

    def fractions(self) -> Dict[str, float]:
        lim = self.limits
        return {
            "tool_calls": self.tool_calls / max(lim.max_tool_calls, 1),
            "seconds": self.elapsed / max(lim.max_seconds, 1e-9),
            "iterations": self.iterations / max(lim.max_iterations, 1),
            "llm_calls": self.llm_calls / max(lim.max_llm_calls, 1),
            "expensive_ops": self.expensive_ops / max(lim.max_expensive_ops, 1),
        }

    def used_fraction(self) -> float:
        return max(self.fractions().values())

    def status(self) -> str:
        f = self.used_fraction()
        if f >= 1.0:
            return "exhausted"
        if f >= self.CRITICAL:
            return "critical"
        if f >= self.CONSTRAINED:
            return "constrained"
        return "ok"

    def can_afford(self, expensive: bool = False, llm: bool = False) -> bool:
        lim = self.limits
        if self.tool_calls >= lim.max_tool_calls or self.elapsed >= lim.max_seconds:
            return False
        if expensive and self.expensive_ops >= lim.max_expensive_ops:
            return False
        if llm and self.llm_calls >= lim.max_llm_calls:
            return False
        return True

    def loop_may_continue(self) -> bool:
        return self.iterations < self.limits.max_iterations and self.can_afford()

    def exhausted_dimensions(self) -> List[str]:
        return [k for k, v in self.fractions().items() if v >= 1.0]

    def snapshot(self) -> Dict[str, object]:
        return {
            "status": self.status(),
            "tool_calls": self.tool_calls,
            "llm_calls": self.llm_calls,
            "expensive_ops": self.expensive_ops,
            "iterations": self.iterations,
            "elapsed_seconds": round(self.elapsed, 2),
            "limits": self.limits.model_dump(),
            "exhausted": self.exhausted_dimensions(),
        }
