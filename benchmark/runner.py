"""
benchmark/runner.py
-------------------
Executes benchmark scenarios through Raven's real assessment pipeline and
collects structured, machine-readable results.

The runner is an observer: it calls `core.assessment.run_assessment` exactly as
the CLI would (same intake, planner, gateway, scope, budget, recovery,
validation, coverage and report code), never reaching inside to fabricate a
finding or relax a control. Each scenario is set up in an isolated temp
`state_root` and torn down by its own context manager.
"""

from __future__ import annotations

import time
import traceback
from pathlib import Path
from typing import Dict, List, Optional

from core.assessment import run_assessment
from core.models import CoverageStatus, FindingStatus
from reporting.generator import render_markdown

from benchmark.models import CheckResult, Scenario, ScenarioResult, evaluate

_IS_POSIX = __import__("os").name == "posix"


def _unexpected_confirmed(scenario: Scenario, state) -> List[dict]:
    """Confirmed findings the scenario did not enumerate. Surfaced for review;
    never auto-scored, since the benchmark cannot know their ground truth."""
    out = []
    for f in state.confirmed_findings:
        if not any(ef.matches_identity(f) for ef in scenario.expected_findings):
            out.append({"title": f.title, "category": f.category, "validator": f.validator,
                        "location": f.location, "severity": f.severity.value})
    return out


def _metrics(state, duration_s: float, scenario: Scenario) -> dict:
    cov_counts: Dict[str, int] = {}
    for c in state.coverage:
        cov_counts[c.status.value] = cov_counts.get(c.status.value, 0) + 1
    return {
        "duration_s": round(duration_s, 2),
        "tool_calls": len(state.tool_calls),
        "tool_calls_ok": sum(1 for c in state.tool_calls if c.status == "ok"),
        "iterations": (state.budget or {}).get("iterations"),
        "overall_state": state.overall_state,
        "findings_confirmed": len(state.confirmed_findings),
        "findings_inconclusive": len(state.inconclusive_findings),
        "findings_rejected": len(state.rejected_findings),
        "coverage_counts": cov_counts,
        "limitations": len(state.limitations),
        "unexpected_confirmed": _unexpected_confirmed(scenario, state),
    }


async def run_scenario(scenario: Scenario, state_root: Path) -> ScenarioResult:
    """Set up the fixture, run one real assessment, evaluate it, tear down."""
    if scenario.posix_only and not _IS_POSIX:
        return ScenarioResult(scenario.id, scenario.kind, scenario.target_type, "skipped",
                              skip_reason="POSIX-only scenario on a non-POSIX host")
    try:
        with scenario.setup() as target:
            t0 = time.monotonic()
            state = await run_assessment(
                target, depth=scenario.depth, max_risk=scenario.max_risk,
                authorized=True, learn_lessons=False,
                limits=scenario.limits,
                state_root=state_root / scenario.id,
            )
            duration = time.monotonic() - t0
            report_md = render_markdown(state)
    except Exception:                                    # a crash IS a benchmark failure, recorded not hidden
        return ScenarioResult(scenario.id, scenario.kind, scenario.target_type, "error",
                              error=traceback.format_exc(limit=6))

    checks = evaluate(scenario, state, report_md)
    status = "passed" if all(c.passed for c in checks) else "failed"
    return ScenarioResult(scenario.id, scenario.kind, scenario.target_type, status,
                          checks=checks, metrics=_metrics(state, duration, scenario))


async def run_scenarios(scenarios: List[Scenario], state_root: Path) -> List[ScenarioResult]:
    results = []
    for sc in scenarios:
        results.append(await run_scenario(sc, state_root))
    return results


# ── aggregation ───────────────────────────────────────────────────────────────

def _accuracy(results: List[ScenarioResult], prefix: str) -> Dict[str, int]:
    """Count passed/total across all checks whose name starts with `prefix`,
    over scenarios that actually ran (not skipped/errored)."""
    passed = total = 0
    for r in results:
        if r.status in ("skipped", "error"):
            continue
        for c in r.checks:
            if c.name.startswith(prefix):
                total += 1
                passed += bool(c.passed)
    return {"passed": passed, "total": total}


def summarize(results: List[ScenarioResult]) -> dict:
    by_status: Dict[str, int] = {}
    for r in results:
        by_status[r.status] = by_status.get(r.status, 0) + 1
    ran = [r for r in results if r.status not in ("skipped", "error")]
    total_unexpected = sum(len(r.metrics.get("unexpected_confirmed", [])) for r in ran)
    total_tool_calls = sum(r.metrics.get("tool_calls", 0) for r in ran)
    total_duration = round(sum(r.metrics.get("duration_s", 0.0) for r in ran), 2)
    return {
        "scenarios_total": len(results),
        "passed": by_status.get("passed", 0),
        "failed": by_status.get("failed", 0),
        "skipped": by_status.get("skipped", 0),
        "error": by_status.get("error", 0),
        "detection_accuracy": _accuracy(results, "finding["),
        "coverage_accuracy": _accuracy(results, "coverage["),
        "false_positive_gate": _accuracy(results, "no_false_positive["),
        "report_consistency": _accuracy(results, "report_"),
        "unexpected_confirmed_total": total_unexpected,
        "tool_calls_total": total_tool_calls,
        "duration_s_total": total_duration,
    }


def exit_code(summary: dict) -> int:
    """0 only when nothing failed or errored; skipped scenarios do not fail the run."""
    return 1 if (summary.get("failed") or summary.get("error")) else 0


def build_report(results: List[ScenarioResult], meta: Optional[dict] = None) -> dict:
    return {
        "meta": meta or {},
        "summary": summarize(results),
        "scenarios": [r.to_dict() for r in results],
    }
