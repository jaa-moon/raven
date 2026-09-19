"""
reporting/generator.py
----------------------
Renders an AssessmentState as a human-readable report. The report is honest
by construction: there is no "Clean" verdict, "no findings" is always
qualified by coverage, and every limitation Raven knows about is listed.
"""

from __future__ import annotations

from pathlib import Path
from typing import List

from core.models import SEVERITY_RANK, CoverageStatus, Finding, Observation
from core.state import AssessmentState

_STATE_TEXT = {
    "COMPLETE": "COMPLETE - every applicable surface was assessed.",
    "PARTIAL": "PARTIAL - some applicable surfaces were only partly assessed or not assessed.",
    "INCOMPLETE": "INCOMPLETE - little or nothing could be assessed.",
    "INCONCLUSIVE": "INCONCLUSIVE - no applicable surface could be identified.",
}


def _sorted(findings: List[Finding]) -> List[Finding]:
    return sorted(findings, key=lambda f: -SEVERITY_RANK[f.severity.value])


def _duration(state: AssessmentState) -> str:
    from datetime import datetime
    try:
        a, b = datetime.fromisoformat(state.started_at), datetime.fromisoformat(state.finished_at or state.started_at)
        return f"{(b - a).total_seconds():.0f}s"
    except ValueError:
        return "n/a"


def verdict(state: AssessmentState) -> str:
    """The sentence that replaces 'Clean'. Never implies the target is secure."""
    confirmed = state.confirmed_findings
    items = [c for c in state.coverage if c.status != CoverageStatus.NOT_APPLICABLE]
    assessed = sum(1 for c in items if c.status == CoverageStatus.ASSESSED)
    if confirmed:
        top = _sorted(confirmed)[0].severity.value
        return (f"{len(confirmed)} confirmed finding(s), highest severity {top}. "
                f"Coverage: {assessed} of {len(items)} applicable surfaces fully assessed.")
    return (f"No confirmed findings. This is NOT evidence that the target is secure: only {assessed} of "
            f"{len(items)} applicable surfaces were fully assessed"
            f"{', and ' + str(len(state.inconclusive_findings)) + ' item(s) remain inconclusive' if state.inconclusive_findings else ''}.")


def render_markdown(state: AssessmentState) -> str:
    p, t = state.profile, state.target
    md: List[str] = ["# Raven Security Assessment Report", ""]
    md += [f"- **Assessment ID**: `{state.assessment_id}`",
           f"- **Target**: `{t.normalized_target if t else p.target}` ({p.target_type})",
           f"- **Duration**: {_duration(state)}  |  **Tool calls**: {len(state.tool_calls)}",
           f"- **Overall assessment state**: **{_STATE_TEXT.get(state.overall_state, state.overall_state)}**", ""]

    md += ["## Executive Summary", "", verdict(state), ""]
    md += [f"- Confirmed findings: **{len(state.confirmed_findings)}**",
           f"- Inconclusive findings: **{len(state.inconclusive_findings)}**",
           f"- Rejected candidates (false positives filtered out): **{len(state.rejected_findings)}**",
           f"- Limitations recorded: **{len(state.limitations)}**", ""]

    md += ["## Target Profile", "",
           f"- Type: `{p.target_type}`  |  Reachable: `{p.reachable}`",
           f"- Surfaces: {', '.join(p.surfaces) or 'none identified'}",
           f"- Technologies: {', '.join(p.technologies) or 'none identified'}",
           f"- Authentication: `{p.authentication}`  |  API: `{p.api}`  |  Source available: `{p.source_available}`", ""]

    md += _findings_section("Confirmed Findings", _sorted(state.confirmed_findings))
    md += _findings_section("Inconclusive Findings", _sorted(state.inconclusive_findings), brief=True)
    md += _path_discovery(state)

    md += ["## Coverage", "", "| Surface | Status | Detail |", "|---|---|---|"]
    for c in state.coverage:
        md.append(f"| {c.surface} | {c.status.value} | {c.detail.replace('|', '/')} |")
    md.append("")

    md += ["## Limitations", ""]
    md += [f"- {x}" for x in state.limitations] or ["- None recorded."]
    md += [""]

    b = state.budget or {}
    md += ["## Budget and Recovery", "",
           f"- Budget status: `{b.get('status', 'n/a')}`; tool calls {b.get('tool_calls', 0)}/"
           f"{(b.get('limits') or {}).get('max_tool_calls', '?')}; iterations {b.get('iterations', 0)}",
           f"- Recovery decisions recorded: {len(state.recovery_actions)}"]
    for r in state.recovery_actions[:10]:
        md.append(f"  - {r.capability}: {r.failure_type} -> {r.action} ({r.detail[:80]})")
    md += [""]

    md += ["## Method", "",
           f"- Plan revisions: {state.plan.version}; tasks: {len(state.tasks)} "
           f"({len(state.completed_tasks)} done, {len(state.failed_tasks)} failed, {len(state.skipped_tasks)} skipped/blocked)",
           f"- Knowledge retrievals during the run: {len(state.rag_contexts)}",
           f"- Validated lessons stored: {len(state.lessons_learned)}", ""]
    return "\n".join(md)


def _findings_section(title: str, findings: List[Finding], brief: bool = False) -> List[str]:
    md = [f"## {title} ({len(findings)})", ""]
    if not findings:
        return md + ["None.", ""]
    for f in findings:
        md += [f"### [{f.severity.value.upper()}] {f.title}",
               f"- Surface: {f.surface}  |  Location: `{f.location}`  |  Confidence: **{f.confidence.value}**  |  Validator: `{f.validator}`",
               f"- Description: {f.description}"]
        if f.validation_notes:
            md.append(f"- Validation performed: {' '.join(f.validation_notes)}")
        if brief:
            md.append("")
            continue
        if f.impact:
            md.append(f"- Impact: {f.impact}")
        for e in f.evidence:
            md.append(f"- Evidence ({e.kind}): {e.summary}")
        if f.reproduction:
            md += ["- Reproduction:", "  ```", *[f"  {r}" for r in f.reproduction], "  ```"]
        if f.remediation:
            md.append(f"- Remediation: {f.remediation}")
        md.append("")
    return md


def _path_discovery(state: AssessmentState) -> List[str]:
    obs: List[Observation] = [o for o in state.observations if o.kind == "path.candidate"]
    if not obs:
        return []
    by_class: dict = {}
    for o in obs:
        by_class[o.data.get("classification", "unknown")] = by_class.get(o.data.get("classification", "unknown"), 0) + 1
    confirmed_paths = {f.signal.get("path") for f in state.confirmed_findings if f.signal.get("path")}
    md = ["## Path Discovery Summary", "",
          "Discovered paths are listed separately from validated vulnerabilities: a path that answers is a *candidate*, "
          "not a finding.", "",
          f"- Candidate paths tested: {len(obs)}",
          f"- Likely SPA fallback responses: {by_class.get('spa_fallback', 0)}",
          f"- Confirmed exposures (validated): {len(confirmed_paths)}",
          f"- Protected (401/403): {by_class.get('protected', 0)}", "",
          "| Path | Status | Content-Type | Classification | Validated finding |", "|---|---|---|---|---|"]
    for o in obs:
        d = o.data
        md.append(f"| `{d.get('path')}` | {d.get('status')} | {d.get('content_type', '') or '-'} | "
                  f"{d.get('classification')} | {'yes' if d.get('path') in confirmed_paths else 'no'} |")
    return md + [""]


def save(state: AssessmentState, out_dir: Path) -> tuple:
    out_dir.mkdir(parents=True, exist_ok=True)
    md_path = out_dir / f"raven_{state.assessment_id}.md"
    json_path = out_dir / f"raven_{state.assessment_id}.json"
    md_path.write_text(render_markdown(state), encoding="utf-8")
    json_path.write_text(state.model_dump_json(indent=2), encoding="utf-8")
    return md_path, json_path
