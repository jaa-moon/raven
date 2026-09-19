"""
tests/test_budget_manager.py
----------------------------
Unit tests for BudgetLimits, BudgetManager reservation, and exhaustion.
"""

from engine.budget_manager import BudgetLimits, BudgetManager
from engine_models.state import AssessmentState


def test_budget_limits_presets():
    quick = BudgetLimits.for_depth("quick")
    assert quick.max_tool_calls == 30
    assert quick.max_requests in (100, 150)

    deep = BudgetLimits.for_depth("deep")
    assert deep.max_tool_calls in (200, 350)
    assert deep.max_requests in (2000, 2500)


def test_budget_consumption_and_exhaustion():
    limits = BudgetLimits(max_tool_calls=5, max_requests=10, max_runtime_seconds=60)
    bm = BudgetManager(limits)

    assert bm.can_afford(calls=2, requests=4) is True
    bm.consume(tool_calls=2, requests=4)
    assert bm.remaining_calls() == 3
    assert bm.remaining_requests() == 6

    # Consume remaining calls
    bm.consume(tool_calls=3, requests=1)
    assert bm.can_afford(calls=1) is False
    assert bm.is_exhausted() is True


def test_budget_state_sync():
    limits = BudgetLimits(max_tool_calls=50, max_requests=100)
    bm = BudgetManager(limits)
    bm.consume(tool_calls=7, requests=15)

    state = AssessmentState(assessment_id="ASM-TEST")
    bm.sync_to_state(state)

    assert state.total_tool_calls == 7
    assert state.total_requests_made == 15
    assert state.elapsed_seconds >= 0.0
