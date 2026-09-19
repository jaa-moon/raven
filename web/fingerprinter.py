"""
web/fingerprinter.py
--------------------
Raven Phase 8: Technology stack and security posture fingerprinter.

Analyses crawl results to identify:
  - Web server and application technology (nginx, Django, WordPress, etc.)
  - Security header presence / absence
  - Cookie security flags
  - Interesting administrative / sensitive paths
  - Basic TLS info
  - Information disclosure artifacts (version numbers, stack traces)

Uses only the crawl results already in memory — does NOT make additional
HTTP requests, except for the interesting-path probes which are quick
HEAD/GET requests against a known list.
"""

from __future__ import annotations

import logging
import re
import time
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlparse

import requests

from web.crawler import CrawlResult
from web.content_validators import (
    ValidationState,
    get_validator_for_path,
    validate_admin_panel,
)
from web.response_classifier import ResponseClass, classify_response
from web.spa_fallback_detector import SPAFallbackDetector

logger = logging.getLogger(__name__)

# ── Security header checklist ─────────────────────────────────────────────────

REQUIRED_SECURITY_HEADERS: list[str] = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
]

# ── Interesting paths to probe ────────────────────────────────────────────────

INTERESTING_PATHS: list[str] = [
    "/.git/HEAD",
    "/.env",
    "/.env.production",
    "/.env.local",
    "/admin",
    "/administrator",
    "/api",
    "/api/v1",
    "/api/v2",
    "/swagger",
    "/swagger-ui.html",
    "/api-docs",
    "/graphql",
    "/console",
    "/actuator",
    "/actuator/health",
    "/actuator/env",
    "/phpinfo.php",
    "/server-status",
    "/server-info",
    "/robots.txt",
    "/sitemap.xml",
    "/.well-known/security.txt",
    "/wp-login.php",
    "/wp-admin",
    "/wp-config.php",
    "/config.php",
    "/configuration.php",
    "/app/config/parameters.yml",
    "/debug",
]

# ── Technology fingerprint signatures ─────────────────────────────────────────

#: (pattern_in_body, technology_name)
BODY_SIGNATURES: list[tuple[re.Pattern, str]] = [
    (re.compile(r"/wp-content/", re.I),             "WordPress"),
    (re.compile(r"wp-includes",  re.I),             "WordPress"),
    (re.compile(r"Joomla!",      re.I),             "Joomla"),
    (re.compile(r"Drupal",       re.I),             "Drupal"),
    (re.compile(r"Django",       re.I),             "Django"),
    (re.compile(r"Laravel",      re.I),             "Laravel"),
    (re.compile(r"Ruby on Rails",re.I),             "Ruby on Rails"),
    (re.compile(r"react(?:dom)?\.(?:development|production)\.min\.js", re.I), "React"),
    (re.compile(r"__next",       re.I),             "Next.js"),
    (re.compile(r"nuxt",         re.I),             "Nuxt.js"),
    (re.compile(r"angular\.min\.js", re.I),         "Angular"),
    (re.compile(r"vue\.(?:min\.)?js", re.I),        "Vue.js"),
    (re.compile(r"jquery[\-\.]\d+", re.I),          "jQuery"),
    (re.compile(r"bootstrap\.min", re.I),           "Bootstrap"),
    (re.compile(r"struts",       re.I),             "Apache Struts"),
    (re.compile(r"jsessionid",   re.I),             "Java/JEE"),
    (re.compile(r"__viewstate",  re.I),             "ASP.NET WebForms"),
    (re.compile(r"asp\.net",     re.I),             "ASP.NET"),
    (re.compile(r"flask",        re.I),             "Flask"),
    (re.compile(r"express",      re.I),             "Express.js"),
    (re.compile(r"fastapi",      re.I),             "FastAPI"),
    (re.compile(r"shopify",      re.I),             "Shopify"),
    (re.compile(r"magento",      re.I),             "Magento"),
    (re.compile(r"grafana",      re.I),             "Grafana"),
    (re.compile(r"kibana",       re.I),             "Kibana"),
]

#: Header-based technology signatures: (header_name, value_pattern, tech_name)
HEADER_SIGNATURES: list[tuple[str, re.Pattern, str]] = [
    ("Server",          re.compile(r"nginx",        re.I),   "nginx"),
    ("Server",          re.compile(r"apache",       re.I),   "Apache"),
    ("Server",          re.compile(r"IIS",          re.I),   "IIS"),
    ("Server",          re.compile(r"lighttpd",     re.I),   "Lighttpd"),
    ("Server",          re.compile(r"gunicorn",     re.I),   "Gunicorn"),
    ("Server",          re.compile(r"cloudflare",   re.I),   "Cloudflare"),
    ("X-Powered-By",    re.compile(r"PHP",          re.I),   "PHP"),
    ("X-Powered-By",    re.compile(r"Express",      re.I),   "Express.js"),
    ("X-Powered-By",    re.compile(r"ASP\.NET",     re.I),   "ASP.NET"),
    ("X-Generator",     re.compile(r".*"),                   "CMS"),
    ("X-Drupal",        re.compile(r".*"),                   "Drupal"),
    ("X-Shopify-Stage", re.compile(r".*"),                   "Shopify"),
]

#: Cookie names that reveal technology
COOKIE_TECH: dict[str, str] = {
    "PHPSESSID":        "PHP",
    "JSESSIONID":       "Java/JEE",
    "ASP.NET_SessionId":"ASP.NET",
    "wordpress_":       "WordPress",
    "wp-settings-":     "WordPress",
    "AWSALB":           "AWS ALB",
    "AWSELB":           "AWS ELB",
    "__cfduid":         "Cloudflare",
    "cf_clearance":     "Cloudflare",
    "_rails_session":   "Ruby on Rails",
    "laravel_session":  "Laravel",
    "django":           "Django",
}

#: Patterns in body that indicate information disclosure
DISCLOSURE_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"Traceback \(most recent call last\)", re.I), "Python stack trace exposed"),
    (re.compile(r"at \S+\.java:\d+",                   re.I), "Java stack trace exposed"),
    (re.compile(r"ORA-\d{5}",                          re.I), "Oracle DB error exposed"),
    (re.compile(r"Microsoft OLE DB Provider",           re.I), "MSSQL error exposed"),
    (re.compile(r"PHP Notice|PHP Warning|PHP Fatal",    re.I), "PHP error exposed"),
    (re.compile(r"MySQLSyntaxErrorException",           re.I), "MySQL error exposed"),
    (re.compile(r"DEBUG\s*=\s*True",                    re.I), "Debug mode enabled"),
    (re.compile(r"SECRET_KEY\s*=",                      re.I), "Secret key disclosed"),
    (re.compile(r"API_KEY\s*=",                         re.I), "API key in response"),
    (re.compile(r"password\s*=\s*['\"][^'\"]+['\"]",    re.I), "Hardcoded password in response"),
]


# ── Output dataclasses ────────────────────────────────────────────────────────

@dataclass
class HeaderStatus:
    """Security header presence and value."""
    present: bool
    value: str
    secure: bool      # True = the value looks well-configured


@dataclass
class CookieAnalysis:
    """Security analysis of a single HTTP cookie."""
    name: str
    has_httponly: bool
    has_secure: bool
    has_samesite: bool
    is_session: bool      # True = no Expires/Max-Age → session cookie


@dataclass
class PathDiscovery:
    """Result of testing a single candidate path, distinct from a confirmed finding."""
    path: str
    status: int
    content_type: str
    response_length: int
    classification: str            # ResponseClass value
    similarity_to_baseline: Optional[float]
    validation_state: str          # ValidationState value
    confidence: str
    evidence: list[str] = field(default_factory=list)
    reason: str = ""
    vulnerability_type: str = ""
    severity: str = "Info"


@dataclass
class SiteFingerprint:
    """Full fingerprint of the scanned site."""
    detected_technologies: list[str] = field(default_factory=list)
    server_header: str = ""
    security_headers: dict[str, HeaderStatus] = field(default_factory=dict)
    missing_security_headers: list[str] = field(default_factory=list)
    cookies: list[CookieAnalysis] = field(default_factory=list)
    interesting_paths: list[str] = field(default_factory=list)
    path_discoveries: list[PathDiscovery] = field(default_factory=list)
    tls_info: dict = field(default_factory=dict)
    information_disclosures: list[str] = field(default_factory=list)


# ── Fingerprinter ─────────────────────────────────────────────────────────────

class SiteFingerprinter:
    """Analyses crawl results to identify technology stack and security posture.

    Args:
        timeout:    HTTP timeout for interesting-path probes (default 8s).
        verify_ssl: Whether to verify SSL certificates (default True).
        user_agent: User-Agent string for probe requests.
    """

    def __init__(
        self,
        timeout: int = 8,
        verify_ssl: bool = True,
        user_agent: str = "RavenScanner/1.0 (Authorized Security Test)",
    ) -> None:
        self._timeout    = timeout
        self._verify_ssl = verify_ssl
        self._session    = requests.Session()
        self._session.headers.update({"User-Agent": user_agent})

    def fingerprint(self, crawl_result: CrawlResult) -> SiteFingerprint:
        """Run all fingerprint checks on the crawl result.

        Returns a SiteFingerprint with all detected attributes.
        """
        fp = SiteFingerprint()
        techs: set[str] = set()

        # Aggregate all response headers and body snippets from the crawl
        all_headers: list[dict[str, str]] = []
        all_bodies:  list[str]           = []
        all_cookies_raw: list[str]        = []

        for page in crawl_result.pages:
            all_headers.append(page.response_headers)
            all_bodies.append(page.raw_body_snippet)
            raw_cookie = page.response_headers.get("Set-Cookie", "")
            if raw_cookie:
                all_cookies_raw.append(raw_cookie)

        # Use headers from the very first page as the "representative" set
        rep_headers = all_headers[0] if all_headers else {}

        # ── Server header ──────────────────────────────────────────────────────
        fp.server_header = rep_headers.get("Server", "")

        # ── Security headers ───────────────────────────────────────────────────
        for header_name in REQUIRED_SECURITY_HEADERS:
            # Case-insensitive search across all page headers
            found_val = ""
            for h in all_headers:
                for k, v in h.items():
                    if k.lower() == header_name.lower():
                        found_val = v
                        break
                if found_val:
                    break

            present = bool(found_val)
            fp.security_headers[header_name] = HeaderStatus(
                present=present,
                value=found_val,
                secure=self._is_secure_header_value(header_name, found_val),
            )
            if not present:
                fp.missing_security_headers.append(header_name)

        # ── Technology detection — headers ─────────────────────────────────────
        for header_name, pattern, tech in HEADER_SIGNATURES:
            for h in all_headers:
                for k, v in h.items():
                    if k.lower() == header_name.lower() and pattern.search(v):
                        techs.add(tech)

        # ── Technology detection — body ────────────────────────────────────────
        combined_body = "\n".join(all_bodies[:10])   # sample first 10 pages
        for pattern, tech in BODY_SIGNATURES:
            if pattern.search(combined_body):
                techs.add(tech)

        # ── Cookie analysis ────────────────────────────────────────────────────
        cookies_seen: set[str] = set()
        for raw in all_cookies_raw:
            ca = self._parse_cookie(raw)
            if ca and ca.name not in cookies_seen:
                fp.cookies.append(ca)
                cookies_seen.add(ca.name)
                # Cookie-based tech detection
                for cookie_prefix, tech in COOKIE_TECH.items():
                    if ca.name.lower().startswith(cookie_prefix.lower()):
                        techs.add(tech)

        # ── Information disclosure ─────────────────────────────────────────────
        for pattern, description in DISCLOSURE_PATTERNS:
            if pattern.search(combined_body):
                fp.information_disclosures.append(description)

        # ── Interesting path probing ───────────────────────────────────────────
        base = crawl_result.base_url
        base_parsed = urlparse(base)
        origin = f"{base_parsed.scheme}://{base_parsed.netloc}"

        detector = SPAFallbackDetector(fetcher=lambda p: self._fetch(origin + p))
        try:
            baseline = detector.establish_baseline()
            logger.info(
                "SPA-fallback baseline established: status=%s content_type=%s length=%s",
                baseline.status_code, baseline.content_type, baseline.response_length,
            )
        except Exception:
            logger.warning("Failed to establish SPA-fallback baseline; proceeding without it.", exc_info=True)
            baseline = None

        for path in INTERESTING_PATHS:
            status, headers, body = self._fetch(origin + path)
            discovery = self._evaluate_path(path, status, headers, body, detector if baseline else None)
            fp.path_discoveries.append(discovery)
            if discovery.validation_state in (ValidationState.CONFIRMED.value, ValidationState.PROTECTED.value):
                fp.interesting_paths.append(f"{path} [{status}] ({discovery.validation_state})")

        # ── TLS info ───────────────────────────────────────────────────────────
        if base_parsed.scheme == "https":
            fp.tls_info = {"scheme": "HTTPS", "note": "TLS in use"}
        else:
            fp.tls_info = {"scheme": "HTTP", "note": "No TLS — connection is unencrypted"}
            techs.discard("Cloudflare")  # CDN detection less reliable on HTTP

        fp.detected_technologies = sorted(techs)
        return fp

    # ── Private helpers ────────────────────────────────────────────────────────

    def _fetch(self, url: str) -> tuple[int, dict, str]:
        """GET *url* and return (status_code, headers, body_text), or (0, {}, "") on error."""
        try:
            resp = self._session.get(
                url,
                timeout=self._timeout,
                verify=self._verify_ssl,
                allow_redirects=False,
            )
            return resp.status_code, dict(resp.headers), resp.text
        except Exception:
            return 0, {}, ""

    def _evaluate_path(
        self,
        path: str,
        status: int,
        headers: dict,
        body: str,
        detector: Optional[SPAFallbackDetector],
    ) -> "PathDiscovery":
        """Classify a candidate-path response and run its content-specific validator.

        HTTP 200 is never treated as confirmation on its own: the response is
        first classified against the SPA-fallback baseline, and only a
        response that both differs from the baseline AND passes a
        content-specific check can reach ValidationState.CONFIRMED.
        """
        classification = classify_response(path, status, headers, body, detector)

        validator = get_validator_for_path(path)
        if validator is None:
            # No content-specific validator for this path — never auto-confirm.
            if classification.classification == ResponseClass.SPA_FALLBACK:
                state, confidence, evidence, reason = (
                    ValidationState.SPA_FALLBACK, "None", [], classification.reason,
                )
            elif classification.classification == ResponseClass.PROTECTED:
                state, confidence, evidence, reason = (
                    ValidationState.PROTECTED, "Medium",
                    [f"HTTP {status} — access restricted."], classification.reason,
                )
            elif classification.classification == ResponseClass.REAL_RESOURCE:
                state, confidence, evidence, reason = (
                    ValidationState.INCONCLUSIVE, "Low",
                    [], "No content-specific validator exists for this path; discovery only.",
                )
            else:
                state, confidence, evidence, reason = (
                    ValidationState.FALSE_POSITIVE, "None", [], classification.reason,
                )
            return PathDiscovery(
                path=path, status=status, content_type=classification.content_type,
                response_length=classification.length,
                classification=classification.classification.value,
                similarity_to_baseline=classification.similarity_to_baseline,
                validation_state=state.value, confidence=confidence,
                evidence=evidence, reason=reason,
            )

        if validator is validate_admin_panel:
            baseline_title = detector.baseline.title if (detector and detector.baseline) else ""
            outcome = validator(classification, body, baseline_title)
        else:
            outcome = validator(classification, body)

        return PathDiscovery(
            path=path, status=status, content_type=classification.content_type,
            response_length=classification.length,
            classification=classification.classification.value,
            similarity_to_baseline=classification.similarity_to_baseline,
            validation_state=outcome.state.value, confidence=outcome.confidence,
            evidence=outcome.evidence, reason=outcome.reason,
            vulnerability_type=outcome.vulnerability_type, severity=outcome.severity,
        )

    def _parse_cookie(self, raw_header: str) -> Optional[CookieAnalysis]:
        """Parse a Set-Cookie header value into a CookieAnalysis."""
        if not raw_header:
            return None
        parts = [p.strip() for p in raw_header.split(";")]
        if not parts:
            return None

        # First part is name=value
        name_val = parts[0]
        name = name_val.split("=")[0].strip()
        if not name:
            return None

        directives = [p.lower() for p in parts[1:]]
        return CookieAnalysis(
            name=name,
            has_httponly="httponly" in directives,
            has_secure="secure" in directives,
            has_samesite=any(d.startswith("samesite") for d in directives),
            is_session=not any(
                d.startswith("expires") or d.startswith("max-age")
                for d in directives
            ),
        )

    @staticmethod
    def _is_secure_header_value(header: str, value: str) -> bool:
        """Heuristic check whether the header value is reasonably configured."""
        if not value:
            return False
        h = header.lower()
        v = value.lower()
        if h == "x-frame-options":
            return "deny" in v or "sameorigin" in v
        if h == "x-content-type-options":
            return "nosniff" in v
        if h == "strict-transport-security":
            return "max-age" in v
        if h == "referrer-policy":
            return v in (
                "no-referrer", "strict-origin", "strict-origin-when-cross-origin",
                "same-origin",
            )
        return bool(value)
