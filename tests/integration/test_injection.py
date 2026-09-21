"""
End-to-end active injection testing through the real pipeline: discover
surface -> hypothesis -> capability request -> Gateway (scope+budget) ->
controlled probe -> observation -> independent validation -> coverage ->
report. Against a local, deliberately (and safely) vulnerable fixture.
"""

from __future__ import annotations

import pytest

from core.budget import BudgetLimits
from core.models import CoverageStatus, FindingStatus
from reporting.generator import render_markdown

FAST = dict(authorized=True, learn_lessons=False)
GENEROUS = BudgetLimits(max_tool_calls=200, max_iterations=120, max_expensive_ops=30, max_llm_calls=50)


def _by_category(state, category):
    return [f for f in state.findings if f.category == category]


# ── end-to-end confirmation, one per injection type ────────────────────────────

async def test_sql_injection_is_discovered_probed_and_confirmed_end_to_end(vulnerable_server):
    from core.assessment import run_assessment
    state = await run_assessment(vulnerable_server.url, max_risk="moderate",
                                 limits=GENEROUS, **FAST)
    sqli = _by_category(state, "SQLInjection")
    assert sqli and sqli[0].status == FindingStatus.CONFIRMED
    assert sqli[0].validator == "sql_injection"
    assert any(h.type.value == "sql_injection" and h.finding_id for h in state.injection_hypotheses)


async def test_reflected_xss_is_discovered_probed_and_confirmed_end_to_end(vulnerable_server):
    from core.assessment import run_assessment
    state = await run_assessment(vulnerable_server.url, max_risk="moderate",
                                 limits=GENEROUS, **FAST)
    xss = _by_category(state, "CrossSiteScripting")
    assert xss and xss[0].status == FindingStatus.CONFIRMED
    assert xss[0].validator == "reflected_xss"


async def test_ssrf_is_discovered_probed_and_confirmed_end_to_end(vulnerable_server):
    from core.assessment import run_assessment
    state = await run_assessment(vulnerable_server.url, max_risk="moderate",
                                 limits=GENEROUS, **FAST)
    ssrf = _by_category(state, "ServerSideRequestForgery")
    assert ssrf and ssrf[0].status == FindingStatus.CONFIRMED
    assert ssrf[0].validator == "ssrf"


# ── scope enforcement: active testing is off by default, never silently ───────

async def test_active_testing_is_blocked_by_default_scope_and_recorded_honestly(vulnerable_server):
    from core.assessment import run_assessment
    state = await run_assessment(vulnerable_server.url, limits=GENEROUS, **FAST)
    assert not _by_category(state, "SQLInjection")
    assert not _by_category(state, "CrossSiteScripting")
    assert not _by_category(state, "ServerSideRequestForgery")
    assert any("max-risk moderate" in l for l in state.limitations)
    assert all(c.status != "out_of_scope" for c in state.tool_calls)          # never even attempted
    cov = {c.surface: c for c in state.coverage}
    assert cov["SQL Injection"].status == CoverageStatus.NOT_ASSESSED
    assert cov["XSS"].status == CoverageStatus.NOT_ASSESSED
    assert cov["SSRF"].status == CoverageStatus.NOT_ASSESSED
    md = render_markdown(state)
    assert "clean" not in md.lower()


# ── coverage / reporting honesty ────────────────────────────────────────────────

async def test_injection_coverage_is_assessed_when_active_testing_ran(vulnerable_server):
    from core.assessment import run_assessment
    state = await run_assessment(vulnerable_server.url, max_risk="moderate",
                                 limits=GENEROUS, **FAST)
    cov = {c.surface: c for c in state.coverage}
    assert cov["SQL Injection"].status in (CoverageStatus.ASSESSED, CoverageStatus.PARTIALLY_ASSESSED)
    assert cov["XSS"].status in (CoverageStatus.ASSESSED, CoverageStatus.PARTIALLY_ASSESSED)


async def test_report_includes_active_injection_testing_section(vulnerable_server):
    from core.assessment import run_assessment
    state = await run_assessment(vulnerable_server.url, max_risk="moderate",
                                 limits=GENEROUS, **FAST)
    md = render_markdown(state)
    assert "Active Injection Testing" in md
    assert "sql_injection" in md and "ssrf" in md


# ── budget exhaustion never becomes "not vulnerable" ────────────────────────────

async def test_injection_tasks_are_skipped_not_silently_dropped_under_tight_budget(vulnerable_server):
    from core.assessment import run_assessment
    state = await run_assessment(vulnerable_server.url, max_risk="moderate",
                                 limits=BudgetLimits(max_tool_calls=6), **FAST)
    assert state.overall_state != "COMPLETE"
    assert state.phase == "complete"                                          # degraded gracefully, didn't crash
    skipped_or_pending = [t for t in state.tasks
                          if t.surface in ("SQL Injection", "XSS", "SSRF") and t.status in ("skipped", "pending")]
    all_injection = [t for t in state.tasks if t.surface in ("SQL Injection", "XSS", "SSRF")]
    if all_injection:
        assert skipped_or_pending or any(t.status == "done" for t in all_injection)
    # Whatever ran or didn't, budget exhaustion is never reported as an absence of vulnerabilities.
    for c in state.coverage:
        if c.surface in ("SQL Injection", "XSS", "SSRF") and not _by_category(
                state, {"SQL Injection": "SQLInjection", "XSS": "CrossSiteScripting",
                       "SSRF": "ServerSideRequestForgery"}[c.surface]):
            assert c.status != CoverageStatus.ASSESSED or "test(s) completed" in c.detail


# ── tool failure / recovery reuse the existing controller ──────────────────────

async def test_missing_injection_tools_are_reported_as_a_limitation_not_a_crash(vulnerable_server):
    from agents.registry import default_registry
    from core.assessment import run_assessment
    from raven_mcp.registry import ToolRegistry
    from tools.catalog import build_registry

    full = build_registry()
    limited = ToolRegistry()
    for t in full.all():
        if not any(c.startswith("injection.") for c in t.capabilities):
            limited.register(t)

    state = await run_assessment(vulnerable_server.url, max_risk="moderate", tools=limited,
                                 agents=default_registry(), limits=BudgetLimits(max_tool_calls=100), **FAST)
    assert state.phase == "complete"                                          # never crashes on a missing tool
    assert any("injection.sql.detect" in l or "injection.xss.reflect" in l or "injection.ssrf.detect" in l
              for l in state.limitations)
    assert not _by_category(state, "SQLInjection")
    blocked = [t for t in state.tasks if t.surface in ("SQL Injection", "XSS", "SSRF")]
    assert blocked and all(t.status == "blocked" for t in blocked)
