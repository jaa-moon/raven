"""
core/models.py
--------------
Pydantic models for Raven Phase 8 web scanning module.

These models are used by the web/ package (crawler, fingerprinter,
probe_engine, ai_probe_advisor, web_report_generator).
"""

from __future__ import annotations

from datetime import datetime
from typing import Dict, List, Literal, Optional

from pydantic import BaseModel, Field


# ── Vulnerability type enum (string-based for flexibility) ────────────────────

WebVulnType = Literal[
    "SQLi",
    "XSS",
    "SSRF",
    "LFI",
    "OpenRedirect",
    "HeaderInjection",
]


# ── Individual web finding ────────────────────────────────────────────────────

class WebFinding(BaseModel):
    """A single confirmed or suspected web vulnerability."""

    finding_id: str = ""
    vulnerability_type: str = ""
    severity: str = "Info"  # Critical | High | Medium | Low | Info
    url: str = ""
    method: str = "GET"
    parameter: str = ""
    payload_sent: str = ""
    evidence: str = ""
    http_status: int = 0
    confirmed: bool = False
    ai_analysis: str = ""
    remediation: str = ""
    curl_poc: str = ""


# ── Aggregated web scan report ────────────────────────────────────────────────

class WebScanReport(BaseModel):
    """Complete output of a web vulnerability scan."""

    target: str = ""
    scan_type: str = "Active Web Scan"
    timestamp: str = Field(default_factory=lambda: datetime.now().isoformat())
    scan_duration_seconds: float = 0.0
    fingerprint: Dict = Field(default_factory=dict)
    findings: List[WebFinding] = Field(default_factory=list)
    findings_by_severity: Dict[str, int] = Field(default_factory=dict)
    total_findings: int = 0
    report_path: str = ""
