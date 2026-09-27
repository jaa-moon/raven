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

def _confirmed(findings):
    return [f for f in findings if f.status == FindingStatus.CONFIRMED]


async def test_sql_injection_is_discovered_probed_and_confirmed_end_to_end(vulnerable_server):
    # Input-surface discovery v2 also raises SQLi candidates on spec-derived and
    # sniffed-path parameters that this fixture never actually mishandles, so more
    # than one SQLInjection candidate can legitimately exist; only the real /search
    # `q` vulnerability should ever be CONFIRMED, and never index-0-by-accident.
    from core.assessment import run_assessment
    state = await run_assessment(vulnerable_server.url, max_risk="moderate",
                                 limits=GENEROUS, **FAST)
    sqli = _by_category(state, "SQLInjection")
    confirmed = _confirmed(sqli)
    assert confirmed and confirmed[0].validator == "sql_injection"
    assert any(h.type.value == "sql_injection" and h.finding_id for h in state.injection_hypotheses)


async def test_reflected_xss_is_discovered_probed_and_confirmed_end_to_end(vulnerable_server):
    from core.assessment import run_assessment
    state = await run_assessment(vulnerable_server.url, max_risk="moderate",
                                 limits=GENEROUS, **FAST)
    xss = _by_category(state, "CrossSiteScripting")
    confirmed = _confirmed(xss)
    assert confirmed and confirmed[0].validator == "reflected_xss"


async def test_ssrf_is_discovered_probed_and_confirmed_end_to_end(vulnerable_server):
    from core.assessment import run_assessment
    state = await run_assessment(vulnerable_server.url, max_risk="moderate",
                                 limits=GENEROUS, **FAST)
    ssrf = _by_category(state, "ServerSideRequestForgery")
    confirmed = _confirmed(ssrf)
    assert confirmed and confirmed[0].validator == "ssrf"


# ── input-surface discovery: action-less forms are found and tested ───────────

async def test_actionless_form_parameter_is_discovered_and_tested(vulnerable_server):
    from core.assessment import run_assessment
    state = await run_assessment(vulnerable_server.url, max_risk="moderate",
                                 limits=GENEROUS, **FAST)
    surface = state.profile.attributes.get("injection_surface", {})
    all_params = {p["name"] for v in surface.values() for p in v.get("params", [])}
    assert "token" in all_params                                    # action-less form on "/" was parsed
    assert any(h.parameter == "token" for h in state.injection_hypotheses)


# ── input-surface discovery v2: path segments, cookies, OpenAPI/Swagger ────────

async def test_rest_path_id_segment_is_discovered_and_tested_as_a_path_parameter(vulnerable_server):
    from core.assessment import run_assessment
    state = await run_assessment(vulnerable_server.url, max_risk="moderate",
                                 limits=GENEROUS, **FAST)
    surface = state.profile.attributes.get("injection_surface", {})
    widget_params = surface.get("/widgets/7", {}).get("params", [])
    assert {"name": "7", "location": "path", "evidence": "observed"} in widget_params
    assert any(h.endpoint == "/widgets/7" and h.location == "path" for h in state.injection_hypotheses)


async def test_set_cookie_names_are_discovered_as_cookie_parameters(vulnerable_server):
    from core.assessment import run_assessment
    state = await run_assessment(vulnerable_server.url, max_risk="moderate",
                                 limits=GENEROUS, **FAST)
    surface = state.profile.attributes.get("injection_surface", {})
    root_params = surface.get("/", {}).get("params", [])
    names = {p["name"]: p for p in root_params}
    assert names["session"]["location"] == "cookie" and names["session"]["evidence"] == "cookie"
    assert "_ga" not in names                                  # analytics cookie excluded, not app input


async def test_openapi_spec_parameters_are_discovered_with_spec_evidence(vulnerable_server):
    from core.assessment import run_assessment
    state = await run_assessment(vulnerable_server.url, max_risk="moderate",
                                 limits=GENEROUS, **FAST)
    surface = state.profile.attributes.get("injection_surface", {})
    product = surface.get("/rest/products/1", {}).get("params", [])
    by_name = {p["name"]: p for p in product}
    assert by_name["verbose"] == {"name": "verbose", "location": "query", "evidence": "spec"}
    assert by_name["1"]["location"] == "path" and by_name["1"]["evidence"] == "spec"
    search = surface.get("/rest/products/search", {}).get("params", [])
    search_names = {p["name"] for p in search}
    assert {"query", "category"} <= search_names
    assert all(p["evidence"] == "spec" and p["location"] == "body"
              for p in search if p["name"] in ("query", "category"))


# ── evidence-aware prioritization: spec/form beat guesses, auth surfaces rank higher ──

def test_spec_evidence_outranks_a_bare_naming_convention_guess():
    from agents.injection import InjectionType, _task_priority
    spec_score = _task_priority(InjectionType.SQL_INJECTION, "/rest/products/1", "verbose", "spec")
    guessed_score = _task_priority(InjectionType.SQL_INJECTION, "/api/Widgets", "id", "guessed")
    assert spec_score > guessed_score


def test_auth_sensitive_endpoint_outranks_an_equally_evidenced_generic_one():
    from agents.injection import InjectionType, _task_priority
    login_score = _task_priority(InjectionType.SQL_INJECTION, "/rest/user/login", "email", "form")
    generic_score = _task_priority(InjectionType.SQL_INJECTION, "/api/Widgets", "email", "form")
    assert login_score > generic_score


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


# ── risk level is recorded and drives honest coverage reasons ─────────────────

def test_report_records_selected_risk_level():
    from core.scope import Scope
    from core.state import AssessmentState
    state = AssessmentState()
    state.scope = Scope(max_risk="moderate")
    md = render_markdown(state)
    assert "Risk level" in md and "moderate" in md and "active injection testing enabled" in md.lower()


async def test_low_risk_injection_coverage_gives_risk_reason_not_clean(vulnerable_server):
    from core.assessment import run_assessment
    state = await run_assessment(vulnerable_server.url, limits=GENEROUS, **FAST)   # default low
    cov = {c.surface: c for c in state.coverage}
    assert cov["SQL Injection"].status == CoverageStatus.NOT_ASSESSED
    assert "risk policy" in cov["SQL Injection"].detail.lower()
    assert "not vulnerable" not in cov["SQL Injection"].detail.lower()


async def test_high_risk_notes_absence_of_additional_high_risk_capabilities(vulnerable_server):
    from core.assessment import run_assessment
    state = await run_assessment(vulnerable_server.url, max_risk="high", limits=GENEROUS, **FAST)
    assert any("no capabilities requiring 'high' risk" in l.lower() for l in state.limitations)
    # High still reaches the controlled active tests (same as moderate).
    assert _by_category(state, "SQLInjection")


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
