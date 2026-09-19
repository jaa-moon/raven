"""
web/response_classifier.py
---------------------------
Classifies a raw HTTP response into a semantic category before any
vulnerability validator sees it. HTTP 200 alone is never sufficient to
call a response a "real resource" — it must also fail to match the
SPA-fallback baseline (see ``web.spa_fallback_detector``).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

from web.spa_fallback_detector import SPAFallbackDetector, _extract_title, _get_header


class ResponseClass(str, Enum):
    REAL_RESOURCE = "real_resource"
    SPA_FALLBACK = "spa_fallback"
    GENERIC_404 = "generic_404"
    REDIRECT = "redirect"
    PROTECTED = "protected"
    SERVER_ERROR = "server_error"
    UNKNOWN = "unknown"


_AUTH_INDICATOR_RE = re.compile(
    r"(login|sign[\s-]?in|unauthorized|access\s+denied|forbidden|authentication\s+required)",
    re.I,
)


@dataclass
class ClassifiedResponse:
    """Structured classification of a single candidate-path response."""

    path: str
    status: int
    content_type: str
    length: int
    classification: ResponseClass
    similarity_to_baseline: Optional[float]
    title: str
    is_json: bool
    redirect_location: str
    auth_indicator: bool
    reason: str


def classify_response(
    path: str,
    status: int,
    headers: dict,
    body: str,
    detector: Optional[SPAFallbackDetector] = None,
) -> ClassifiedResponse:
    """Classify a raw response for *path* using the optional SPA baseline detector.

    A ``200 text/html`` response is NOT automatically ``real_resource`` — it
    is only classified that way once it has been checked against the
    nonexistent-path baseline and found to differ.
    """
    content_type = _get_header(headers, "content-type")
    body = body or ""
    length = len(body)
    title = _extract_title(body)
    is_json = "json" in content_type.lower() or _looks_like_json(body)
    location = _get_header(headers, "location")
    auth_indicator = bool(_AUTH_INDICATOR_RE.search(body)) or bool(_AUTH_INDICATOR_RE.search(title))

    if status == 0:
        return ClassifiedResponse(
            path=path, status=status, content_type=content_type, length=length,
            classification=ResponseClass.UNKNOWN, similarity_to_baseline=None,
            title=title, is_json=is_json, redirect_location=location,
            auth_indicator=auth_indicator,
            reason="Connection error or no response received.",
        )

    if status >= 500:
        return ClassifiedResponse(
            path=path, status=status, content_type=content_type, length=length,
            classification=ResponseClass.SERVER_ERROR, similarity_to_baseline=None,
            title=title, is_json=is_json, redirect_location=location,
            auth_indicator=auth_indicator,
            reason=f"Server returned HTTP {status}.",
        )

    if status in (301, 302, 303, 307, 308):
        return ClassifiedResponse(
            path=path, status=status, content_type=content_type, length=length,
            classification=ResponseClass.REDIRECT, similarity_to_baseline=None,
            title=title, is_json=is_json, redirect_location=location,
            auth_indicator=auth_indicator,
            reason=f"Redirect to '{location}'." if location else "Redirect with no Location header.",
        )

    if status in (401, 403):
        return ClassifiedResponse(
            path=path, status=status, content_type=content_type, length=length,
            classification=ResponseClass.PROTECTED, similarity_to_baseline=None,
            title=title, is_json=is_json, redirect_location=location,
            auth_indicator=auth_indicator,
            reason=f"Access restricted (HTTP {status}) — resource exists but is not readable.",
        )

    if status == 404:
        return ClassifiedResponse(
            path=path, status=status, content_type=content_type, length=length,
            classification=ResponseClass.GENERIC_404, similarity_to_baseline=None,
            title=title, is_json=is_json, redirect_location=location,
            auth_indicator=auth_indicator,
            reason="Not found.",
        )

    # 2xx (and any other unmatched status): consult the SPA baseline before
    # ever calling this a real resource.
    similarity: Optional[float] = None
    if detector is not None and detector.baseline is not None:
        comparison = detector.compare(status, headers, body)
        similarity = comparison.similarity
        if comparison.is_fallback:
            return ClassifiedResponse(
                path=path, status=status, content_type=content_type, length=length,
                classification=ResponseClass.SPA_FALLBACK, similarity_to_baseline=similarity,
                title=title, is_json=is_json, redirect_location=location,
                auth_indicator=auth_indicator,
                reason=comparison.reason,
            )

    if 200 <= status < 300:
        return ClassifiedResponse(
            path=path, status=status, content_type=content_type, length=length,
            classification=ResponseClass.REAL_RESOURCE, similarity_to_baseline=similarity,
            title=title, is_json=is_json, redirect_location=location,
            auth_indicator=auth_indicator,
            reason="Response does not match the SPA-fallback baseline; content-specific validation required.",
        )

    return ClassifiedResponse(
        path=path, status=status, content_type=content_type, length=length,
        classification=ResponseClass.UNKNOWN, similarity_to_baseline=similarity,
        title=title, is_json=is_json, redirect_location=location,
        auth_indicator=auth_indicator,
        reason=f"Unhandled status code {status}.",
    )


def _looks_like_json(body: str) -> bool:
    stripped = body.strip()
    return stripped.startswith("{") or stripped.startswith("[")
