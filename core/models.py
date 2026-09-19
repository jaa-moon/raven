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

    # Evidence-based confidence state. One of: candidate, validated, confirmed,
    # inconclusive, protected, spa_fallback, false_positive. HTTP 200 alone
    # must never set this to "confirmed" — see web.content_validators.
    validation_state: str = "candidate"
    classification: str = ""  # response_classifier.ResponseClass value
    rejection_reason: str = ""


# ── Path discovery (candidate-path scanning) ──────────────────────────────────

class PathDiscoveryEntry(BaseModel):
    """One candidate path tested during sensitive-path / admin-panel discovery.

    This is distinct from WebFinding: every candidate path tested produces
    exactly one PathDiscoveryEntry, regardless of whether it turned into a
    confirmed vulnerability, so the report can show discovery-vs-validation
    honestly (see 'Path Discovery Summary').
    """

    path: str = ""
    http_status: int = 0
    content_type: str = ""
    response_length: int = 0
    classification: str = ""          # response_classifier.ResponseClass value
    similarity_to_baseline: Optional[float] = None
    validation_state: str = "candidate"
    confidence: str = "None"
    evidence: List[str] = Field(default_factory=list)
    reason: str = ""


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
    path_discoveries: List[PathDiscoveryEntry] = Field(default_factory=list)
    path_discovery_summary: Dict[str, int] = Field(default_factory=dict)


# ── AST Context Compression Models (Phase 9) ───────────────────────────────

class CompressedChunk(BaseModel):
    """A single extracted code unit from AST or structural parsing."""

    chunk_id: str
    chunk_type: Literal[
        "function", "method", "class_def",
        "import_block", "global_assignment", "decorator_block"
    ]
    name: str
    line_start: int
    line_end: int
    source: str
    risk_score: float = 0.0
    risk_reasons: List[str] = Field(default_factory=list)
    language: str = "python"
    file_path: str = ""


class CompressionResult(BaseModel):
    """Aggregate output of AST compression on a single file."""

    file_path: str
    language: str
    original_line_count: int = 0
    original_char_count: int = 0
    compressed_char_count: int = 0
    compression_ratio: float = 1.0
    chunks: List[CompressedChunk] = Field(default_factory=list)
    fallback_used: bool = False
    fallback_reason: str = ""

