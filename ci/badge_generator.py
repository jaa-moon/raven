"""
ci/badge_generator.py
---------------------
Generates a Shields.io endpoint-compatible JSON badge describing the current
security posture of the scanned project.

The generated file (``raven-badge.json``) can be hosted on any static CDN or
committed to the repo and served via a GitHub Pages / raw URL, then embedded
in the README as:

    ![Raven Security](https://img.shields.io/endpoint?url=<URL_TO_RAVEN-BADGE.JSON>)

Badge colour logic (based on most severe finding):
  Critical → red
  High     → orange
  Medium   → yellow
  Low      → informational (blue)
  None     → brightgreen (passing)

Schema reference: https://shields.io/endpoint
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)

# ── Severity ranking ──────────────────────────────────────────────────────────

_SEV_RANK: Dict[str, int] = {
    "Critical": 0,
    "High":     1,
    "Medium":   2,
    "Low":      3,
    "Info":     4,
}

_SEV_COLOR: Dict[str, str] = {
    "Critical": "critical",   # red
    "High":     "orange",
    "Medium":   "yellow",
    "Low":      "informational",
    "Info":     "lightgrey",
}

_PASS_COLOR = "brightgreen"


# ── Public API ────────────────────────────────────────────────────────────────

def generate_badge(
    output_path: str,
    scan_report: Optional[object] = None,
    results_json_path: Optional[str] = None,
) -> None:
    """Write a Shields.io endpoint JSON file to *output_path*.

    Exactly one of *scan_report* or *results_json_path* should be supplied.
    If both are given, *results_json_path* takes precedence (useful when the
    badge is generated in a separate CI step that only has the JSON artefact).

    Args:
        output_path:       Destination file path for the badge JSON.
        scan_report:       A completed ``ScanReport`` instance (in-process use).
        results_json_path: Path to the ``raven-results.json`` file (CI step use).
    """
    if results_json_path:
        payload = _badge_from_json(results_json_path)
    elif scan_report is not None:
        payload = _badge_from_report(scan_report)
    else:
        logger.warning("badge_generator: no scan_report or results_json_path provided.")
        return

    if payload is None:
        return

    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    logger.debug("Badge written to %s", out)


# ── Internal helpers ──────────────────────────────────────────────────────────

def _badge_payload(
    label: str,
    message: str,
    color: str,
    is_error: bool = False,
) -> Dict[str, Any]:
    """Build a Shields.io endpoint-compatible payload dict."""
    return {
        "schemaVersion": 1,
        "label":         label,
        "message":       message,
        "color":         color,
        "isError":       is_error,
        "namedLogo":     "shield",
    }


def _badge_from_json(json_path: str) -> Optional[Dict[str, Any]]:
    """Build the badge payload by reading a ``raven-results.json`` file."""
    try:
        data: Dict[str, Any] = json.loads(
            Path(json_path).read_text(encoding="utf-8")
        )
    except Exception as exc:
        logger.warning("badge_generator: could not read %r: %s", json_path, exc)
        return None

    sev_counts: Dict[str, int] = data.get("findings_by_severity", {})
    adv_count  = data.get("adversarial_findings_count", 0)
    total      = data.get("total_findings", 0)

    worst, color = _worst_severity(sev_counts)
    message, is_error = _format_message(total, worst, adv_count)

    return _badge_payload(
        label="raven security",
        message=message,
        color=color,
        is_error=is_error,
    )


def _badge_from_report(report: object) -> Optional[Dict[str, Any]]:
    """Build the badge payload directly from a ``ScanReport`` instance."""
    try:
        findings = list(getattr(report, "findings", []))
    except Exception:
        return None

    sev_counts: Dict[str, int] = {s: 0 for s in _SEV_RANK}
    for f in findings:
        sev = getattr(f, "severity", "Info")
        sev_counts[sev] = sev_counts.get(sev, 0) + 1

    worst, color = _worst_severity(sev_counts)
    message, is_error = _format_message(len(findings), worst, adv_count=0)

    return _badge_payload(
        label="raven security",
        message=message,
        color=color,
        is_error=is_error,
    )


def _worst_severity(
    sev_counts: Dict[str, int]
) -> tuple[Optional[str], str]:
    """Return (worst_severity_label, badge_color) based on finding counts."""
    for sev in ("Critical", "High", "Medium", "Low", "Info"):
        if sev_counts.get(sev, 0) > 0:
            return sev, _SEV_COLOR[sev]
    return None, _PASS_COLOR


def _format_message(
    total: int,
    worst: Optional[str],
    adv_count: int,
) -> tuple[str, bool]:
    """Return (badge_message, is_error) given total findings and worst severity."""
    if total == 0 and adv_count == 0:
        return "passing", False

    parts = []
    if total:
        label = worst.lower() if worst else "findings"
        parts.append(f"{total} {label}")
    if adv_count:
        parts.append(f"{adv_count} red-team")

    msg = " · ".join(parts)
    is_error = worst in ("Critical", "High") if worst else False
    return msg, is_error
