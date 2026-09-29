"""
Unit tests for the assessment benchmark framework itself (benchmark/).

These test the benchmark's own logic -- scenario validation, the expected-vs-
actual comparison, result serialization, failure handling, fixture cleanup and
exit codes -- against synthetic AssessmentStates. They deliberately do NOT run
real assessments (the integration suite and `python -m benchmark` do that); a
framework bug must be catchable without a multi-second pipeline run.
"""

from __future__ import annotations

import json
import os
from contextlib import contextmanager
from pathlib import Path

import pytest

from benchmark.models import (
    ExpectedFinding,
    Scenario,
    evaluate,
    validate_scenario,
    validate_scenarios,
)
from benchmark.runner import build_report, exit_code, run_scenario, summarize
from benchmark import scenarios as S
from core.models import (
    CoverageItem,
    CoverageStatus,
    Evidence,
    Finding,
    FindingStatus,
    Severity,
    TestTask,
    ToolCallRecord,
)
from core.state import AssessmentState
from reporting.generator import render_markdown

CONFIRMED = FindingStatus.CONFIRMED
INCONCLUSIVE = FindingStatus.INCONCLUSIVE


def _state(findings=(), coverage=(), tasks=(), tool_calls=(), overall="PARTIAL"):
    st = AssessmentState()
    st.findings = list(findings)
    st.coverage = list(coverage)
    st.tasks = list(tasks)
    st.tool_calls = list(tool_calls)
    st.overall_state = overall
    st.finished_at = "2026-01-01T00:00:00"
    return st


def _finding(**kw):
    kw.setdefault("title", "A finding")
    kw.setdefault("severity", Severity.HIGH)
    kw.setdefault("status", CONFIRMED)
    kw.setdefault("evidence", [Evidence(kind="tool_output", summary="e")])
    return Finding(**kw)


# ── scenario loading + validation ─────────────────────────────────────────────

def test_real_suite_loads_and_validates():
    assert S.SCENARIOS, "no scenarios defined"
    validate_scenarios(S.SCENARIOS)                       # must not raise
    ids = [s.id for s in S.SCENARIOS]
    assert len(ids) == len(set(ids))                      # unique
    assert S.by_id(ids[0]).id == ids[0]


def test_by_id_unknown_raises():
    with pytest.raises(KeyError):
        S.by_id("no-such-scenario")


def test_validate_rejects_malformed_scenarios():
    good_setup = lambda: iter(())  # noqa: E731  (not called by validation)
    base = dict(target_type="web_application", setup=good_setup,
                expected_coverage={"HTTP": CoverageStatus.ASSESSED})

    with pytest.raises(ValueError, match="kind"):
        validate_scenario(Scenario(id="x", kind="bogus", description="d", **base))
    with pytest.raises(ValueError, match="non-empty"):
        validate_scenario(Scenario(id="  ", kind="positive", description="d", **base))
    # An ExpectedFinding with neither category nor validator is meaningless.
    with pytest.raises(ValueError, match="category and/or validator"):
        validate_scenario(Scenario(id="x", kind="positive", description="d",
                                   target_type="web_application", setup=good_setup,
                                   expected_findings=(ExpectedFinding(CONFIRMED),)))
    # A scenario with no expectations checks nothing.
    with pytest.raises(ValueError, match="no expectations"):
        validate_scenario(Scenario(id="x", kind="positive", description="d",
                                   target_type="web_application", setup=good_setup))


def test_validate_rejects_duplicate_ids():
    setup = lambda: iter(())  # noqa: E731
    a = Scenario(id="dup", kind="positive", target_type="t", description="d", setup=setup,
                 expected_coverage={"HTTP": CoverageStatus.ASSESSED})
    with pytest.raises(ValueError, match="duplicate"):
        validate_scenarios([a, a])


# ── the expected-vs-actual comparison ─────────────────────────────────────────

def test_evaluate_all_expectations_met_passes():
    f = _finding(category="SensitiveFileExposure", validator="http_path_exposure",
                 location="http://h/.env", title="Exposed /.env")
    st = _state(
        findings=[f],
        coverage=[CoverageItem(surface="Exposed paths & files", status=CoverageStatus.ASSESSED, detail="1 test")],
        tasks=[TestTask(key="web.probe", agent="web", capability="http_request", surface="X", status="done")],
        tool_calls=[ToolCallRecord(request_id="r1", capability="http_request", tool="http", status="ok")],
    )
    sc = Scenario(
        id="s", kind="positive", target_type="web_application", description="d", setup=lambda: iter(()),
        expected_capabilities=("http_request",), expected_tools=("http_request",),
        expected_findings=(ExpectedFinding(CONFIRMED, validator="http_path_exposure",
                                           location_contains="/.env"),),
        expected_coverage={"Exposed paths & files": CoverageStatus.ASSESSED},
        expected_overall="PARTIAL",
    )
    checks = evaluate(sc, st, render_markdown(st))
    failed = [c for c in checks if not c.passed]
    assert not failed, [f"{c.name}: {c.detail}" for c in failed]


def test_evaluate_detects_missing_and_wrong_verdict_and_false_positive():
    # An inconclusive finding where the scenario expected a confirmed one, plus a
    # confirmed finding the scenario forbids.
    inconclusive = _finding(validator="code_pattern", status=INCONCLUSIVE, location="app.py:6", title="shell")
    fp = _finding(validator="sql_injection", status=CONFIRMED, location="http://h/search", title="SQLi")
    st = _state(findings=[inconclusive, fp])
    sc = Scenario(
        id="s", kind="mixed", target_type="web_application", description="d", setup=lambda: iter(()),
        expected_findings=(
            ExpectedFinding(CONFIRMED, validator="code_pattern", location_contains="app.py:6", label="dbg"),
            ExpectedFinding(CONFIRMED, validator="secret_in_file", label="secret"),   # never produced
        ),
        forbidden_findings=(ExpectedFinding(CONFIRMED, validator="sql_injection", label="sqli"),),
    )
    by_name = {c.name: c for c in evaluate(sc, st, render_markdown(st))}
    assert by_name["finding[dbg]==confirmed"].passed is False
    assert "inconclusive" in by_name["finding[dbg]==confirmed"].detail
    assert by_name["finding[secret]==confirmed"].passed is False
    assert "never produced" in by_name["finding[secret]==confirmed"].detail
    assert by_name["no_false_positive[sqli]"].passed is False
    assert "FALSE POSITIVE" in by_name["no_false_positive[sqli]"].detail


def test_evaluate_multiple_candidates_pass_if_any_reaches_expected_status():
    # Two SQLInjection candidates: one inconclusive, one confirmed. Expecting a
    # confirmed one must pass (the real vuln), not fail on the first candidate.
    cand = _finding(category="SQLInjection", validator="sql_injection", status=INCONCLUSIVE, title="c1")
    real = _finding(category="SQLInjection", validator="sql_injection", status=CONFIRMED, title="c2")
    st = _state(findings=[cand, real])
    sc = Scenario(id="s", kind="positive", target_type="web_application", description="d",
                  setup=lambda: iter(()),
                  expected_findings=(ExpectedFinding(CONFIRMED, category="SQLInjection"),))
    check = next(c for c in evaluate(sc, st, render_markdown(st)) if c.name.startswith("finding["))
    assert check.passed is True


def test_evaluate_coverage_overclaim_fails():
    st = _state(coverage=[CoverageItem(surface="SQL Injection", status=CoverageStatus.NOT_ASSESSED, detail="gated")])
    sc = Scenario(id="s", kind="positive", target_type="web_application", description="d",
                  setup=lambda: iter(()),
                  expected_coverage={"SQL Injection": CoverageStatus.ASSESSED})
    check = next(c for c in evaluate(sc, st, render_markdown(st)) if c.name.startswith("coverage["))
    assert check.passed is False and "NOT_ASSESSED" in check.detail


def test_evaluate_report_state_consistency_detects_mismatch():
    f = _finding(validator="http_path_exposure", status=CONFIRMED, title="Exposed", location="/x")
    st = _state(findings=[f],
                coverage=[CoverageItem(surface="HTTP", status=CoverageStatus.ASSESSED, detail="d")])
    real_md = render_markdown(st)
    ok = next(c for c in evaluate(sc_min(), st, real_md) if c.name == "report_state_consistency")
    assert ok.passed is True
    # A truncated report (missing the coverage table / confirmed count) is caught.
    bad = next(c for c in evaluate(sc_min(), st, "# empty report") if c.name == "report_state_consistency")
    assert bad.passed is False


def sc_min():
    return Scenario(id="s", kind="positive", target_type="web_application", description="d",
                    setup=lambda: iter(()),
                    expected_coverage={"HTTP": CoverageStatus.ASSESSED})


# ── serialization ─────────────────────────────────────────────────────────────

def test_scenario_result_and_report_are_json_serializable():
    st = _state(findings=[_finding(validator="http_path_exposure", title="T", location="/x")],
                coverage=[CoverageItem(surface="HTTP", status=CoverageStatus.ASSESSED, detail="d")])
    sc = sc_min()
    from benchmark.models import ScenarioResult
    checks = evaluate(sc, st, render_markdown(st))
    result = ScenarioResult(sc.id, sc.kind, sc.target_type,
                            "passed" if all(c.passed for c in checks) else "failed", checks=checks,
                            metrics={"tool_calls": 3, "unexpected_confirmed": []})
    report = build_report([result], meta={"commit": "abc"})
    blob = json.dumps(report)                              # must not raise
    round_trip = json.loads(blob)
    assert round_trip["summary"]["scenarios_total"] == 1
    assert round_trip["scenarios"][0]["id"] == "s"
    assert "detection_accuracy" in round_trip["summary"]


# ── failure handling ──────────────────────────────────────────────────────────

async def test_run_scenario_records_setup_failure_as_error(tmp_path):
    @contextmanager
    def _boom():
        raise RuntimeError("fixture blew up")
        yield  # pragma: no cover

    sc = Scenario(id="boom", kind="positive", target_type="web_application", description="d",
                  setup=_boom, expected_coverage={"HTTP": CoverageStatus.ASSESSED})
    res = await run_scenario(sc, tmp_path)                 # must not propagate
    assert res.status == "error" and "fixture blew up" in res.error


async def test_run_scenario_skips_posix_only_off_posix(tmp_path, monkeypatch):
    monkeypatch.setattr("benchmark.runner._IS_POSIX", False)
    sc = Scenario(id="p", kind="positive", target_type="binary", description="d",
                  setup=lambda: iter(()), posix_only=True,
                  expected_coverage={"File permissions": CoverageStatus.ASSESSED})
    res = await run_scenario(sc, tmp_path)
    assert res.status == "skipped" and "POSIX" in res.skip_reason


# ── fixture cleanup ───────────────────────────────────────────────────────────

def test_source_tree_fixture_creates_then_cleans_up():
    with S._source_tree({"a/b.txt": "hi"}) as target:
        p = Path(target)
        assert (p / "a" / "b.txt").read_text() == "hi"
    assert not p.exists()                                  # torn down on exit


def test_binary_fixture_creates_then_cleans_up():
    with S._binary(b"\x7fELFdata", name="x.elf") as target:
        p = Path(target)
        assert p.exists() and p.read_bytes().startswith(b"\x7fELF")
    assert not p.parent.exists()


# ── exit codes + summary ──────────────────────────────────────────────────────

def test_exit_code_and_summary_reflect_outcomes():
    from benchmark.models import CheckResult, ScenarioResult
    passing = ScenarioResult("a", "positive", "web_application", "passed",
                             checks=[CheckResult("finding[x]==confirmed", True)],
                             metrics={"tool_calls": 2, "duration_s": 0.1, "unexpected_confirmed": []})
    failing = ScenarioResult("b", "positive", "web_application", "failed",
                             checks=[CheckResult("coverage[HTTP]==ASSESSED", False, "actual=NOT_ASSESSED")],
                             metrics={"tool_calls": 1, "duration_s": 0.1, "unexpected_confirmed": []})
    skipped = ScenarioResult("c", "positive", "binary", "skipped", skip_reason="POSIX-only")

    assert exit_code(summarize([passing, skipped])) == 0   # skipped alone does not fail
    assert exit_code(summarize([passing, failing])) == 1
    s = summarize([passing, failing, skipped])
    assert s["passed"] == 1 and s["failed"] == 1 and s["skipped"] == 1
    assert s["detection_accuracy"] == {"passed": 1, "total": 1}
    assert s["coverage_accuracy"] == {"passed": 0, "total": 1}
