"""
benchmark/
----------
A small, reproducible benchmark for Raven's *actual* assessment behaviour.

Each scenario runs the real assessment pipeline (intake -> analysis -> planner
-> MCP gateway -> agents -> independent validation -> coverage -> report) end
to end against a controlled, local, authorized fixture, then compares the
resulting AssessmentState and rendered report against a declared expected
outcome. It measures assessment *outcomes* -- was the right capability planned,
did the tool actually run, was the right finding produced, did independent
validation reach the right verdict, was coverage classified honestly, does the
report carry the evidence -- not whether individual functions return expected
values (the unit/integration suite already does that).

Nothing here weakens or bypasses a security control, fabricates a finding, or
changes the core architecture: the benchmark is purely an observer.
"""

from benchmark.models import (
    CheckResult,
    ExpectedFinding,
    Scenario,
    ScenarioResult,
    evaluate,
)

__all__ = ["CheckResult", "ExpectedFinding", "Scenario", "ScenarioResult", "evaluate"]
