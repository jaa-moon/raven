"""
benchmark/models.py
-------------------
Scenario / expectation / result data model and the deterministic comparison
that turns an AssessmentState + rendered report into a list of pass/fail checks.

Design rules that keep the benchmark honest:
  * An expected finding is matched by *identity* (category / validator /
    location substring) first; only then is its validation status compared. A
    missing finding ("never produced") is reported distinctly from a wrong
    verdict ("produced but validated differently").
  * A negative scenario asserts a *forbidden* finding is never CONFIRMED -- that
    is the false-positive gate.
  * Coverage is compared per surface against the honest expected status, so an
    over-claim (NOT_ASSESSED reported as ASSESSED, or the reverse) fails.
  * Confirmed findings a scenario did not enumerate are recorded as
    `unexpected_confirmed` for human review, never silently ignored and never
    auto-counted as either success or false positive.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, ContextManager, Dict, List, Optional

from core.models import CoverageStatus, FindingStatus
from core.state import AssessmentState

# A scenario's setup is a zero-arg factory returning a context manager that
# yields the target string (URL / host:port / path) and cleans up on exit.
SetupFactory = Callable[[], ContextManager[str]]


@dataclass(frozen=True)
class ExpectedFinding:
    """Identity of a finding the scenario expects, plus the validation verdict
    it must reach. At least one of category/validator must be set."""

    status: FindingStatus
    category: Optional[str] = None
    validator: Optional[str] = None
    location_contains: Optional[str] = None
    label: str = ""

    def identity(self) -> str:
        parts = [p for p in (self.category, self.validator, self.location_contains) if p]
        return self.label or "/".join(parts) or "<any>"

    def matches_identity(self, f) -> bool:
        if self.category is not None and f.category != self.category:
            return False
        if self.validator is not None and f.validator != self.validator:
            return False
        if self.location_contains is not None and self.location_contains not in (f.location or ""):
            return False
        return True


@dataclass(frozen=True)
class Scenario:
    """One controlled, authorized assessment scenario with a declared expected
    outcome. `kind` documents intent (positive/negative/inconclusive/partial);
    it does not change how checks run -- the expectations themselves encode it."""

    id: str
    kind: str                                   # positive | negative | inconclusive | partial
    target_type: str
    description: str
    setup: SetupFactory
    depth: str = "standard"
    max_risk: str = "low"
    expected_capabilities: tuple = ()           # capabilities whose task must reach status "done"
    expected_tools: tuple = ()                  # capabilities that must appear in tool_calls with status ok
    expected_findings: tuple = ()               # ExpectedFinding[] that must be produced with the given status
    forbidden_findings: tuple = ()              # ExpectedFinding[] (status ignored) that must NOT be CONFIRMED
    expected_coverage: Dict[str, CoverageStatus] = field(default_factory=dict)
    expected_overall: Optional[str] = None      # AssessmentState.overall_state, if asserted
    limits: object = None                        # optional BudgetLimits (e.g. generous budget for injection)
    posix_only: bool = False                    # skip honestly on a non-POSIX host
    notes: str = ""


@dataclass
class CheckResult:
    name: str
    passed: bool
    detail: str = ""

    def to_dict(self) -> dict:
        return {"name": self.name, "passed": self.passed, "detail": self.detail}


@dataclass
class ScenarioResult:
    id: str
    kind: str
    target_type: str
    status: str                                 # passed | failed | skipped | error
    checks: List[CheckResult] = field(default_factory=list)
    metrics: dict = field(default_factory=dict)
    skip_reason: str = ""
    error: str = ""

    @property
    def failed_checks(self) -> List[CheckResult]:
        return [c for c in self.checks if not c.passed]

    def to_dict(self) -> dict:
        return {
            "id": self.id, "kind": self.kind, "target_type": self.target_type,
            "status": self.status, "skip_reason": self.skip_reason, "error": self.error,
            "metrics": self.metrics,
            "checks": [c.to_dict() for c in self.checks],
        }


# ── comparison ────────────────────────────────────────────────────────────────

_KINDS = {"positive", "negative", "inconclusive", "partial", "mixed"}


def validate_scenario(sc: Scenario) -> None:
    """Raise ValueError if a scenario is malformed, so a bad definition fails
    loudly at load time instead of producing a meaningless result."""
    if not (sc.id and sc.id.strip()):
        raise ValueError("scenario id must be a non-empty string")
    if sc.kind not in _KINDS:
        raise ValueError(f"{sc.id}: kind {sc.kind!r} not one of {sorted(_KINDS)}")
    if not sc.target_type:
        raise ValueError(f"{sc.id}: target_type is required")
    if not callable(sc.setup):
        raise ValueError(f"{sc.id}: setup must be callable")
    for ef in tuple(sc.expected_findings) + tuple(sc.forbidden_findings):
        if ef.category is None and ef.validator is None:
            raise ValueError(f"{sc.id}: an ExpectedFinding must set category and/or validator")
    if not (sc.expected_findings or sc.forbidden_findings or sc.expected_coverage
            or sc.expected_capabilities or sc.expected_tools or sc.expected_overall):
        raise ValueError(f"{sc.id}: scenario declares no expectations to check")


def validate_scenarios(scenarios) -> None:
    """Validate a whole suite and reject duplicate ids."""
    seen = set()
    for sc in scenarios:
        validate_scenario(sc)
        if sc.id in seen:
            raise ValueError(f"duplicate scenario id: {sc.id}")
        seen.add(sc.id)


def _first_matching(findings, ef: ExpectedFinding):
    for f in findings:
        if ef.matches_identity(f):
            return f
    return None


def evaluate(scenario: Scenario, state: AssessmentState, report_md: str) -> List[CheckResult]:
    """Turn an assessment result into pass/fail checks against the scenario's
    declared expectations. Pure and deterministic given (scenario, state, md)."""
    checks: List[CheckResult] = []

    # 1. The assessment ran to completion (did not crash or hang).
    completed = state.overall_state in ("COMPLETE", "PARTIAL", "INCOMPLETE", "INCONCLUSIVE") \
        and state.finished_at is not None
    checks.append(CheckResult("assessment_completed", completed,
                              f"overall={state.overall_state}, finished_at={state.finished_at!r}"))

    # 2. Expected capabilities were actually planned AND their task ran (status done).
    for cap in scenario.expected_capabilities:
        done = [t for t in state.tasks if t.capability == cap and t.status == "done"]
        present = [t for t in state.tasks if t.capability == cap]
        detail = (f"task done" if done else
                  (f"present but status={present[0].status}" if present else "no task planned"))
        checks.append(CheckResult(f"capability_selected:{cap}", bool(done), detail))

    # 3. Expected tools actually executed through the gateway (a real run, not just a plan).
    for cap in scenario.expected_tools:
        ran = [c for c in state.tool_calls if c.capability == cap and c.status == "ok"]
        any_attempt = [c for c in state.tool_calls if c.capability == cap]
        detail = (f"ran ({ran[0].tool})" if ran else
                  (f"attempted, status={any_attempt[0].status}" if any_attempt else "never called"))
        checks.append(CheckResult(f"tool_ran:{cap}", bool(ran), detail))

    # 4. Expected findings: produced (identity match) AND validated to the expected status.
    #    Several candidates can share a category (e.g. multiple SQLInjection
    #    candidates, only one real), so the check is "some finding with this
    #    identity reached the expected status", with a distinct message when the
    #    finding was produced but every match landed on a different verdict.
    for ef in scenario.expected_findings:
        matches = [f for f in state.findings if ef.matches_identity(f)]
        if not matches:
            checks.append(CheckResult(f"finding[{ef.identity()}]=={ef.status.value}", False,
                                      "finding was never produced"))
        elif any(f.status == ef.status for f in matches):
            checks.append(CheckResult(f"finding[{ef.identity()}]=={ef.status.value}", True,
                                      f"produced ({len(matches)} candidate(s)), status reached"))
        else:
            seen = sorted({f.status.value for f in matches})
            checks.append(CheckResult(f"finding[{ef.identity()}]=={ef.status.value}", False,
                                      f"produced but verdict(s)={seen} (expected {ef.status.value})"))

    # 5. Forbidden findings: never CONFIRMED (the false-positive gate for negative cases).
    for ff in scenario.forbidden_findings:
        confirmed = [f for f in state.confirmed_findings if ff.matches_identity(f)]
        checks.append(CheckResult(f"no_false_positive[{ff.identity()}]", not confirmed,
                                  "not confirmed" if not confirmed
                                  else f"FALSE POSITIVE: {confirmed[0].title!r} at {confirmed[0].location!r}"))

    # 6. Coverage classification is honest, per surface.
    cov = {c.surface: c for c in state.coverage}
    for surface, expected in scenario.expected_coverage.items():
        actual = cov.get(surface)
        ok = actual is not None and actual.status == expected
        checks.append(CheckResult(f"coverage[{surface}]=={expected.value}", ok,
                                  "missing surface" if actual is None
                                  else f"actual={actual.status.value}"))

    # 7. Overall assessment state, if the scenario pins it.
    if scenario.expected_overall is not None:
        ok = state.overall_state == scenario.expected_overall
        checks.append(CheckResult(f"overall_state=={scenario.expected_overall}", ok,
                                  f"actual={state.overall_state}"))

    # 8. Report evidence: every expected CONFIRMED finding is visible in the rendered report.
    for ef in scenario.expected_findings:
        if ef.status != FindingStatus.CONFIRMED:
            continue
        f = _first_matching(state.confirmed_findings, ef)
        if f is None:
            continue  # already failed in check 4; don't double-count
        in_report = (f.title in report_md) or (f.location and f.location in report_md)
        checks.append(CheckResult(f"report_evidence[{ef.identity()}]", in_report,
                                  "present in report" if in_report else "confirmed finding missing from report"))

    # 9. Report <-> state consistency: the report's headline numbers and coverage
    #    table must match the persisted state (which is what the JSON report is).
    md_confirmed_ok = f"Confirmed findings: **{len(state.confirmed_findings)}**" in report_md
    cov_rows_ok = all(f"| {c.surface} | {c.status.value} |" in report_md for c in state.coverage)
    checks.append(CheckResult("report_state_consistency", md_confirmed_ok and cov_rows_ok,
                              f"confirmed_count_match={md_confirmed_ok}, coverage_rows_match={cov_rows_ok}"))

    return checks
