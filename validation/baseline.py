"""
web/spa_fallback_detector.py
-----------------------------
Detects Single-Page-Application (SPA) fallback responses.

Many modern frontends (React/Vue/Angular apps served by a dev server or a
static host with history-mode routing) respond to *any* unknown path with
HTTP 200 and the same `index.html` shell. Naively treating a 200 response
to a sensitive-looking path (``/.env``, ``/admin``, ``/.git/HEAD``, ...) as
proof that the resource exists produces false positives against this class
of application (OWASP Juice Shop being a canonical example).

This module establishes a baseline response by requesting a guaranteed
nonexistent path, normalizes both the baseline and each candidate response
to remove dynamic content (timestamps, nonces, CSRF tokens, hashed asset
filenames, random ids, ...), and compares them with a similarity score.
Responses that are highly similar to the baseline are classified as
``spa_fallback`` and must not be forwarded to vulnerability validators.
"""

from __future__ import annotations

import difflib
import hashlib
import re
import uuid
from dataclasses import dataclass, field
from typing import Callable, Optional

#: Response fetched via (status_code, headers, body) tuples.
Fetcher = Callable[[str], tuple[int, dict, str]]

# Similarity ratio (0..1) at or above which a candidate is considered the
# same underlying document as the baseline.
DEFAULT_SIMILARITY_THRESHOLD = 0.92

# ── Normalization patterns for dynamic content ────────────────────────────────

_DYNAMIC_PATTERNS: list[tuple[re.Pattern, str]] = [
    # Hashed / fingerprinted asset filenames: main.3f8a9c2e.js, app-h4sh.css
    (re.compile(r'([./_-])[0-9a-fA-F]{6,32}(\.(?:js|css|map|chunk\.js))', re.I), r"\1<HASH>\2"),
    # UUIDs
    (re.compile(r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}'), "<UUID>"),
    # ISO-ish timestamps
    (re.compile(r'\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?'), "<TIMESTAMP>"),
    # Unix epoch-like long numbers (10-13 digits) often used as cache busters
    (re.compile(r'\b\d{10,13}\b'), "<EPOCH>"),
    # nonce="..." / nonce='...'
    (re.compile(r'nonce=["\'][^"\']*["\']', re.I), 'nonce="<NONCE>"'),
    # CSRF token meta/hidden-input values
    (re.compile(r'((?:csrf|xsrf)[-_]?token["\']?\s*[:=]\s*["\'])[^"\']*(["\'])', re.I), r"\1<CSRF>\2"),
    # Generic query-string cache-busting params: ?v=..., &_=...
    (re.compile(r'([?&](?:v|_|ver|cb|t)=)[^"\'&\s]+', re.I), r"\1<CACHEBUST>"),
    # Any other long hex-looking token (build ids, etc.)
    (re.compile(r'\b[0-9a-fA-F]{16,64}\b'), "<HEX>"),
]

_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)
_SCRIPT_SRC_RE = re.compile(r'<script[^>]+src=["\']([^"\']+)["\']', re.I)
_LINK_HREF_RE = re.compile(r'<link[^>]+href=["\']([^"\']+)["\']', re.I)

#: Substrings in normalized script/style src attributes that hint at a
#: frontend framework runtime (used only as descriptive metadata).
_FRAMEWORK_MARKERS: list[tuple[re.Pattern, str]] = [
    (re.compile(r'react', re.I), "React"),
    (re.compile(r'vue', re.I), "Vue"),
    (re.compile(r'angular', re.I), "Angular"),
    (re.compile(r'__next|next[/-]static', re.I), "Next.js"),
    (re.compile(r'nuxt', re.I), "Nuxt.js"),
]


def _normalize_body(body: str) -> str:
    """Strip dynamic/runtime-generated content so structurally identical
    documents compare as equal regardless of nonces, hashes, timestamps."""
    normalized = body
    for pattern, replacement in _DYNAMIC_PATTERNS:
        normalized = pattern.sub(replacement, normalized)
    # Collapse whitespace so formatting differences don't affect similarity.
    normalized = re.sub(r"\s+", " ", normalized).strip()
    return normalized


def _extract_title(body: str) -> str:
    m = _TITLE_RE.search(body)
    return m.group(1).strip() if m else ""


def _extract_assets(body: str) -> tuple[list[str], list[str]]:
    scripts = _SCRIPT_SRC_RE.findall(body)
    styles = _LINK_HREF_RE.findall(body)
    return scripts, styles


def _detect_framework_markers(body: str, scripts: list[str], styles: list[str]) -> list[str]:
    haystack = body + " " + " ".join(scripts) + " " + " ".join(styles)
    markers = []
    for pattern, name in _FRAMEWORK_MARKERS:
        if pattern.search(haystack) and name not in markers:
            markers.append(name)
    return markers


@dataclass
class SPAFallbackBaseline:
    """Fingerprint of the response returned for a guaranteed nonexistent path."""

    probe_path: str
    status_code: int
    content_type: str
    response_length: int
    normalized_body: str
    body_hash: str
    title: str
    script_srcs: list[str] = field(default_factory=list)
    style_hrefs: list[str] = field(default_factory=list)
    framework_markers: list[str] = field(default_factory=list)


@dataclass
class FallbackComparison:
    """Result of comparing a candidate response against the SPA baseline."""

    is_fallback: bool
    similarity: float
    reason: str


class SPAFallbackDetector:
    """Establishes an SPA-fallback baseline and classifies candidate responses.

    ``fetcher`` is a callable ``(path) -> (status_code, headers, body)`` so
    the detector can be exercised in tests without real network access.
    """

    def __init__(
        self,
        fetcher: Optional[Fetcher] = None,
        similarity_threshold: float = DEFAULT_SIMILARITY_THRESHOLD,
    ) -> None:
        self._fetcher = fetcher
        self._threshold = similarity_threshold
        self._baseline: Optional[SPAFallbackBaseline] = None

    @property
    def baseline(self) -> Optional[SPAFallbackBaseline]:
        return self._baseline

    @staticmethod
    def new_probe_path() -> str:
        """A path that cannot exist on any sane server."""
        return f"/raven-nonexistent-{uuid.uuid4().hex[:12]}"

    def load_baseline(self, probe_path: str, status: int, headers: dict, body: str) -> SPAFallbackBaseline:
        """Build the baseline from a response fetched elsewhere (e.g. via the gateway)."""
        self._baseline = self._build_fingerprint(probe_path, status, headers, body)
        return self._baseline

    def establish_baseline(self) -> SPAFallbackBaseline:
        """Request a guaranteed-nonexistent random path and store its fingerprint."""
        if self._fetcher is None:
            raise RuntimeError("No fetcher configured; use load_baseline().")
        probe_path = f"/raven-nonexistent-{uuid.uuid4().hex[:12]}"
        status, headers, body = self._fetcher(probe_path)
        self._baseline = self._build_fingerprint(probe_path, status, headers, body)
        return self._baseline

    def set_baseline(self, baseline: SPAFallbackBaseline) -> None:
        """Allow an externally-established baseline to be reused (e.g. across scans)."""
        self._baseline = baseline

    def _build_fingerprint(
        self, probe_path: str, status: int, headers: dict, body: str
    ) -> SPAFallbackBaseline:
        content_type = _get_header(headers, "content-type")
        normalized = _normalize_body(body or "")
        body_hash = hashlib.sha256(normalized.encode("utf-8", errors="ignore")).hexdigest()
        scripts, styles = _extract_assets(body or "")
        return SPAFallbackBaseline(
            probe_path=probe_path,
            status_code=status,
            content_type=content_type,
            response_length=len(body or ""),
            normalized_body=normalized,
            body_hash=body_hash,
            title=_extract_title(body or ""),
            script_srcs=scripts,
            style_hrefs=styles,
            framework_markers=_detect_framework_markers(body or "", scripts, styles),
        )

    def compare(self, status: int, headers: dict, body: str) -> FallbackComparison:
        """Compare a candidate response against the established baseline."""
        if self._baseline is None:
            raise RuntimeError("SPAFallbackDetector.establish_baseline() must be called first")

        baseline = self._baseline
        content_type = _get_header(headers, "content-type")

        if status != baseline.status_code:
            return FallbackComparison(
                is_fallback=False,
                similarity=0.0,
                reason=f"Status code {status} differs from baseline {baseline.status_code}.",
            )

        candidate_norm = _normalize_body(body or "")

        if candidate_norm == baseline.normalized_body:
            return FallbackComparison(
                is_fallback=True,
                similarity=1.0,
                reason="Normalized response body is identical to the baseline nonexistent-path response.",
            )

        candidate_hash = hashlib.sha256(candidate_norm.encode("utf-8", errors="ignore")).hexdigest()
        if candidate_hash == baseline.body_hash:
            return FallbackComparison(
                is_fallback=True,
                similarity=1.0,
                reason="Normalized response body hash matches the baseline nonexistent-path response.",
            )

        similarity = _similarity_ratio(baseline.normalized_body, candidate_norm)

        title_match = _extract_title(body or "") == baseline.title and bool(baseline.title)
        content_type_match = content_type == baseline.content_type

        is_fallback = similarity >= self._threshold and content_type_match

        if is_fallback:
            reason = (
                f"Response matches the baseline response for a random nonexistent route "
                f"(similarity={similarity:.2%}, content-type matches"
                f"{', title matches' if title_match else ''})."
            )
        else:
            reason = (
                f"Response differs from the SPA-fallback baseline "
                f"(similarity={similarity:.2%}, content-type match={content_type_match})."
            )

        return FallbackComparison(is_fallback=is_fallback, similarity=similarity, reason=reason)


def _similarity_ratio(a: str, b: str) -> float:
    if not a and not b:
        return 1.0
    # difflib is O(n*m) worst case; cap comparison length to keep scans fast.
    max_len = 20000
    return difflib.SequenceMatcher(None, a[:max_len], b[:max_len]).ratio()


def _get_header(headers: dict, name: str) -> str:
    if not headers:
        return ""
    lname = name.lower()
    for k, v in headers.items():
        if k.lower() == lname:
            return v
    return ""
