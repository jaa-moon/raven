"""
web/payloads/__init__.py
------------------------
Payload library package for Raven Phase 8 active web scanning.

Each sub-module exports:
    PAYLOADS: list[str]            — raw payload strings only
    CONTEXTS: list[PayloadContext] — rich metadata per payload

PayloadContext is defined here and imported by all sub-modules.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class PayloadContext:
    """Metadata for a single probe payload.

    Attributes:
        payload:            The raw string to inject.
        injection_type:     Where it should be injected:
                            'query_param' | 'body' | 'header' | 'path'
        expected_indicator: String/pattern to look for in the response that
                            indicates the payload triggered a vulnerability.
                            For time-based payloads, use 'TIME_DELAY:5'
                            (meaning >= 5 seconds delay confirms the vuln).
        severity:           Expected severity if confirmed: Critical | High | Medium | Low.
        vuln_type:          Short vulnerability class label.
    """
    payload: str
    injection_type: str          # query_param | body | header | path
    expected_indicator: str      # what to look for in response
    severity: str                # Critical | High | Medium | Low
    vuln_type: str               # SQLi | XSS | SSRF | LFI | OpenRedirect | HeaderInjection

# Explicitly export the modules so they are available as attributes of web.payloads
from . import sqli
from . import xss
from . import ssrf
from . import lfi
from . import open_redirect
from . import header_injection

__all__ = [
    "PayloadContext",
    "sqli",
    "xss",
    "ssrf",
    "lfi",
    "open_redirect",
    "header_injection",
]

