"""Honest coverage/reporting, state persistence, contextual knowledge and validated learning."""

import pytest

from core.coverage import compute_coverage, overall_state
from core.models import (Confidence, CoverageStatus, Evidence, Finding, FindingStatus, Severity,
                         TestTask)
from core.state import AssessmentState
from intelligence.context import ContextManager
from intelligence.lessons import extract_lessons, learn
from intelligence.rag import KnowledgeBase
from reporting.generator import render_markdown, verdict


def task(surface, status, summary=""):
    return TestTask(key=f"k-{surface}-{status}", surface=surface, status=status, result_summary=summary)


# ── coverage ──────────────────────────────────────────────────────────────────

def test_partial_when_some_tasks_failed():
    items = compute_coverage("web_application", [task("HTTP", "done"), task("HTTP", "failed", "timeout")])
    http = next(i for i in items if i.surface == "HTTP")
    assert http.status == CoverageStatus.PARTIALLY_ASSESSED and "failed" in http.detail


def test_budget_skipped_surface_is_not_assessed_and_says_why():
    items = compute_coverage("web_application", [task("GraphQL", "skipped", "skipped: budget critical")])
    g = next(i for i in items if i.surface == "GraphQL")
    assert g.status == CoverageStatus.NOT_ASSESSED and "budget" in g.detail


def test_blocked_and_not_applicable_and_unimplemented_are_distinct():
    items = {i.surface: i for i in compute_coverage("web_application", [task("Session & cookies", "blocked", "no tool")])}
    assert items["Session & cookies"].status == CoverageStatus.BLOCKED
    assert items["Secrets"].status == CoverageStatus.NOT_APPLICABLE
    assert items["Authorization"].status == CoverageStatus.NOT_ASSESSED          # not implemented
    assert items["Injection & input handling"].status == CoverageStatus.NOT_ASSESSED


def test_authentication_can_never_exceed_partial_without_credentials():
    items = compute_coverage("web_application", [task("Authentication", "done")])
    assert next(i for i in items if i.surface == "Authentication").status == CoverageStatus.PARTIALLY_ASSESSED


def test_empty_plan_is_incomplete_never_complete():
    assert overall_state(compute_coverage("web_application", [])) == "INCOMPLETE"


# ── the "never Clean" guarantee ──────────────────────────────────────────────────

def test_zero_findings_with_low_coverage_is_not_reported_as_clean():
    s = AssessmentState()
    s.profile.target_type = "web_application"
    s.coverage = compute_coverage("web_application", [task("HTTP", "done")])
    s.overall_state = overall_state(s.coverage)
    md = render_markdown(s)
    v = verdict(s)
    assert "NOT evidence that the target is secure" in v
    assert "clean" not in md.lower() and "secure." not in md.lower().replace("not evidence that the target is secure", "")
    assert "PARTIAL" in md


def test_report_lists_limitations_and_separates_confirmed_from_inconclusive():
    s = AssessmentState()
    s.add_limitation("Target rate limited requests")
    s.findings = [
        Finding(title="Confirmed thing", severity=Severity.HIGH, status=FindingStatus.CONFIRMED,
                confidence=Confidence.HIGH, evidence=[Evidence(summary="proof")]),
        Finding(title="Unproven thing", status=FindingStatus.INCONCLUSIVE),
    ]
    md = render_markdown(s)
    assert "Confirmed Findings (1)" in md and "Inconclusive Findings (1)" in md
    assert "Target rate limited requests" in md


# ── state persistence ────────────────────────────────────────────────────────────

def test_state_round_trips_and_is_resumable(tmp_path):
    s = AssessmentState()
    s.profile.add_surface("http")
    s.tasks.append(TestTask(key="a.b", title="t", status="done"))
    s.add_limitation("x")
    s.save(tmp_path)
    loaded = AssessmentState.load(s.assessment_id, tmp_path)
    assert loaded.profile.surfaces == ["http"] and loaded.tasks[0].key == "a.b" and loaded.limitations == ["x"]
    assert s.assessment_id in AssessmentState.list_ids(tmp_path)
    assert not list((tmp_path / s.assessment_id).glob("*.tmp"))       # atomic write leaves no temp files


def test_loading_a_missing_assessment_raises(tmp_path):
    with pytest.raises(FileNotFoundError):
        AssessmentState.load("ASM-none", tmp_path)


# ── contextual RAG ────────────────────────────────────────────────────────────────

def test_retrieval_is_driven_by_context(tmp_path):
    kb = KnowledgeBase(learned_dir=tmp_path)
    spa = kb.retrieve("SPA unknown routes return 200 for /.env", kinds=["lesson", "checklist"], top_k=2)
    assert spa.snippets and "single page application" in spa.snippets[0].title.lower()
    net = kb.retrieve("unauthenticated redis exposed port", kinds=["checklist"], top_k=1)
    assert "network" in net.snippets[0].title.lower()


def test_context_manager_records_references_not_content(tmp_path):
    s = AssessmentState()
    s.profile.target_type, s.profile.technologies = "web_application", ["Express"]
    cm = ContextManager(KnowledgeBase(learned_dir=tmp_path), s)
    cm.for_planning()
    cm.for_task(TestTask(key="k", title="Probe env paths", surface="Exposed paths & files", capability="http_request"))
    assert len(s.rag_contexts) == 2 and set(s.rag_contexts[0]) == {"purpose", "query", "sources"}


def test_agent_context_is_minimal_not_the_whole_state(tmp_path):
    s = AssessmentState()
    for i in range(50):
        s.observations.append(__import__("core.models", fromlist=["Observation"]).Observation(kind="x", surface="HTTP", summary=f"o{i}"))
    ctx = ContextManager(KnowledgeBase(learned_dir=tmp_path), s).agent_context(
        TestTask(key="k", title="Audit headers", surface="HTTP", capability="http_request"))
    assert len(ctx["observations"]) <= 5 and set(ctx) == {"task", "guidance", "observations", "target"}


# ── validated learning ────────────────────────────────────────────────────────────

def _spa_rejected():
    f = Finding(title="Possible exposure", status=FindingStatus.REJECTED, validator="http_path_exposure",
                evidence=[Evidence(kind="baseline_comparison", data={"classification": "spa_fallback"})])
    s = AssessmentState()
    s.findings = [f]
    s.profile.attributes["spa"] = True
    return s


def test_lessons_come_only_from_validated_evidence(tmp_path):
    s = _spa_rejected()
    assert len(extract_lessons(s)) == 1
    s.findings[0].validator = "none"                        # never validated
    assert extract_lessons(s) == []
    s.findings[0].validator, s.findings[0].evidence = "http_path_exposure", []
    assert extract_lessons(s) == []                          # no evidence


def test_candidate_and_low_confidence_findings_teach_nothing():
    s = AssessmentState()
    s.findings = [Finding(title="c"), Finding(status=FindingStatus.CONFIRMED, confidence=Confidence.LOW,
                                              validator="x", evidence=[Evidence()], surface="HTTP", severity=Severity.HIGH)]
    assert extract_lessons(s) == []


def test_learned_lessons_are_stored_deduplicated_and_retrievable(tmp_path):
    kb = KnowledgeBase(learned_dir=tmp_path)
    first = learn(_spa_rejected(), kb)
    second = learn(_spa_rejected(), kb)
    assert len(first) == 1 and second == []
    hit = kb.retrieve("catch-all routing baseline nonexistent route", kinds=["lesson"], top_k=3)
    assert any(s.source.startswith("learned/") for s in hit.snippets)
