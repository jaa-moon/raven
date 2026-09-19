"""
validation/evidence.py
----------------------
Evidence construction with redaction. Nothing sensitive (secret values,
cookie values, authorization headers) ever enters an Evidence record.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

from core.models import Evidence

_SENSITIVE_HEADERS = {"authorization", "cookie", "set-cookie", "x-api-key", "proxy-authorization"}
_SECRET_KEY = re.compile(
    r"(?i)([A-Za-z0-9_.\-]*(?:pass|pwd|secret|token|key|credential|auth)[A-Za-z0-9_.\-]*[\"']?\s*[:=]\s*)"
    r"[\"']?[^\s\"',;]+[\"']?")
_ENV_LINE = re.compile(r"(?m)^(\s*(?:export\s+)?[A-Za-z_][A-Za-z0-9_]*\s*=\s*).+$")
_URL_CREDS = re.compile(r"(?i)([a-z][a-z0-9+.\-]*://[^\s/:@]+:)[^\s/@]+(@)")


def redact_text(text: str) -> str:
    """Mask secret values. Dotenv-shaped lines lose *every* value."""
    text = _URL_CREDS.sub(lambda m: m.group(1) + "<REDACTED>" + m.group(2), text)
    text = _ENV_LINE.sub(lambda m: m.group(1) + "<REDACTED>", text)
    return _SECRET_KEY.sub(lambda m: m.group(1) + "<REDACTED>", text)


def redact_headers(headers: Dict[str, str]) -> Dict[str, str]:
    return {k: ("<REDACTED>" if k.lower() in _SENSITIVE_HEADERS else v) for k, v in headers.items()}


def http_evidence(url: str, data: Dict[str, Any], note: str = "", tool: str = "http_request") -> Evidence:
    body = data.get("body", "") or ""
    return Evidence(
        kind="http_response",
        summary=note or f"HTTP {data.get('status_code')} from {url}",
        source_tool=tool,
        data={
            "url": url,
            "status": data.get("status_code"),
            "content_type": data.get("content_type", ""),
            "length": len(body),
            "headers": redact_headers(data.get("headers", {})),
            "body_excerpt": redact_text(body[:300]),
        },
    )


def baseline_evidence(similarity: Optional[float], classification: str, reason: str) -> Evidence:
    return Evidence(
        kind="baseline_comparison",
        summary=f"Compared against a nonexistent-route baseline: {classification}",
        source_tool="validation.baseline",
        data={
            "classification": classification,
            "similarity": None if similarity is None else round(similarity, 3),
            "reason": reason,
        },
    )


def file_evidence(path: str, lines: List[Dict[str, Any]], note: str) -> Evidence:
    return Evidence(
        kind="file_content",
        summary=note,
        source_tool="file_inspect",
        data={"file": path, "lines": [{"n": ln["n"], "text": redact_text(ln["text"])} for ln in lines[:5]]},
    )
