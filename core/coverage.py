"""
core/coverage.py
----------------
Coverage is a first-class citizen. It is *computed from what actually ran*
(task outcomes), never inferred from "no findings".

Every attack surface Raven knows about is listed for every assessment, with
one of: ASSESSED, PARTIALLY_ASSESSED, NOT_ASSESSED, NOT_APPLICABLE, BLOCKED.
"""

from __future__ import annotations

from typing import Dict, List, Optional

from pydantic import BaseModel

from core.models import CoverageItem, CoverageStatus, TestTask


class SurfaceSpec(BaseModel):
    name: str
    applies_to: List[str]                 # profile.target_type values
    cap_status: Optional[CoverageStatus] = None   # e.g. Authentication can never exceed PARTIAL
    note: str = ""                        # always shown, explains inherent limits
    implemented: bool = True              # False: no capability exists in this build


WEB = ["web_application"]
NET = ["network_service", "host"]
SRC = ["source_repository"]
BIN = ["binary"]

SURFACES: List[SurfaceSpec] = [
    SurfaceSpec(name="HTTP", applies_to=WEB),
    SurfaceSpec(name="Exposed paths & files", applies_to=WEB),
    SurfaceSpec(name="REST API", applies_to=WEB),
    SurfaceSpec(name="GraphQL", applies_to=WEB),
    SurfaceSpec(name="Session & cookies", applies_to=WEB),
    SurfaceSpec(
        name="Authentication", applies_to=WEB, cap_status=CoverageStatus.PARTIALLY_ASSESSED,
        note="Passive review only; no credentials were supplied, so login flows were not exercised.",
    ),
    SurfaceSpec(
        name="Authorization", applies_to=WEB, implemented=False,
        note="Access-control testing needs credentials/roles and is not implemented in this build.",
    ),
    SurfaceSpec(
        name="SQL Injection", applies_to=WEB,
        note="Active probing only covers discovered parameters (forms, query strings, known REST 'id' "
             "convention) and requires --max-risk moderate or higher; it is not a full crawl.",
    ),
    SurfaceSpec(
        name="XSS", applies_to=WEB,
        note="Reflected XSS only, on discovered parameters; DOM-based and stored XSS are not tested.",
    ),
    SurfaceSpec(
        name="SSRF", applies_to=WEB,
        note="Detection relies on a Raven-hosted loopback callback canary; unreachable across most network "
             "boundaries for a remote target, so a rejection there is not proof of absence.",
    ),
    SurfaceSpec(name="Network services", applies_to=NET),
    SurfaceSpec(name="Source code", applies_to=SRC),
    SurfaceSpec(name="Secrets", applies_to=SRC),
    SurfaceSpec(name="Dependencies", applies_to=SRC),
    SurfaceSpec(name="Configuration", applies_to=SRC),
    SurfaceSpec(name="File permissions", applies_to=SRC + BIN),
    SurfaceSpec(name="Process & CLI", applies_to=BIN),
]

_NA_REASON = {
    "Source code": "Source code is not available for this target type.",
    "Secrets": "No source tree available to scan.",
    "Dependencies": "No dependency manifests available.",
    "Configuration": "No configuration files available.",
    "Network services": "Scope is limited to the target endpoint.",
}


def compute_coverage(
    target_type: str,
    tasks: List[TestTask],
    unavailable_surfaces: Optional[Dict[str, str]] = None,
) -> List[CoverageItem]:
    """
    unavailable_surfaces: surface -> reason for surfaces that were applicable but
    could not be tested for a *known external* reason (e.g. missing binary).
    """
    unavailable_surfaces = unavailable_surfaces or {}
    out: List[CoverageItem] = []
    for spec in SURFACES:
        if target_type not in spec.applies_to:
            out.append(CoverageItem(
                surface=spec.name, status=CoverageStatus.NOT_APPLICABLE,
                detail=_NA_REASON.get(spec.name, f"Not applicable to a {target_type} target."),
            ))
            continue

        mine = [t for t in tasks if t.surface == spec.name]
        ids = [t.task_id for t in mine]
        done = [t for t in mine if t.status == "done"]
        failed = [t for t in mine if t.status == "failed"]
        blocked = [t for t in mine if t.status == "blocked"]
        skipped = [t for t in mine if t.status == "skipped"]
        pending = [t for t in mine if t.status in ("pending", "running")]

        if not spec.implemented:
            status, detail = CoverageStatus.NOT_ASSESSED, spec.note
        elif not mine:
            status = CoverageStatus.BLOCKED if spec.name in unavailable_surfaces else CoverageStatus.NOT_ASSESSED
            detail = unavailable_surfaces.get(spec.name, "No test was planned for this surface.")
        elif done and not (failed or blocked or skipped or pending):
            status, detail = CoverageStatus.ASSESSED, f"{len(done)} test(s) completed."
        elif done:
            problems = []
            if failed:
                problems.append(f"{len(failed)} failed")
            if blocked:
                problems.append(f"{len(blocked)} blocked")
            if skipped:
                problems.append(f"{len(skipped)} skipped ({skipped[0].result_summary or 'budget'})")
            if pending:
                problems.append(f"{len(pending)} not run")
            status = CoverageStatus.PARTIALLY_ASSESSED
            detail = f"{len(done)} test(s) completed; " + ", ".join(problems) + "."
        elif blocked or failed:
            status = CoverageStatus.BLOCKED
            first = (blocked or failed)[0]
            detail = first.result_summary or "All tests for this surface failed or were blocked."
        else:
            status = CoverageStatus.NOT_ASSESSED
            detail = (skipped[0].result_summary if skipped else "Planned but not executed.")

        if spec.cap_status == CoverageStatus.PARTIALLY_ASSESSED and status == CoverageStatus.ASSESSED:
            status = CoverageStatus.PARTIALLY_ASSESSED
        if spec.note and spec.implemented:
            detail = f"{detail} {spec.note}".strip()
        out.append(CoverageItem(surface=spec.name, status=status, detail=detail, task_ids=ids))
    return out


def overall_state(items: List[CoverageItem]) -> str:
    """COMPLETE only if every applicable surface is ASSESSED. Never 'clean'."""
    applicable = [i for i in items if i.status != CoverageStatus.NOT_APPLICABLE]
    if not applicable:
        return "INCONCLUSIVE"
    assessed = [i for i in applicable if i.status == CoverageStatus.ASSESSED]
    if len(assessed) == len(applicable):
        return "COMPLETE"
    touched = [i for i in applicable if i.status in (CoverageStatus.ASSESSED, CoverageStatus.PARTIALLY_ASSESSED)]
    if not touched:
        return "INCOMPLETE"
    return "PARTIAL"
