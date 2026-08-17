"""
web/probe_engine.py
-------------------
Raven Phase 8: Active payload sender and orchestrator.

Orchestrates the active testing phase by:
  1. Emitting passive findings from fingerprint data (headers, cookies, paths).
  2. Generating injection tasks from crawled params, forms, AND synthetic fuzzing.
  3. Asking the AI Advisor which payload categories to test.
  4. Injecting payloads with correct query/body/header/path injection.
  5. Performing boolean-blind SQLi comparative analysis.
  6. Checking redirect Location headers for open redirect detection.
  7. Sending responses back to the AI Advisor for confirmation.
  8. Enforcing rate limits, scope restrictions, and safety aborts (429s).
"""

from __future__ import annotations

import logging
import re
import threading
import time
from typing import Literal
from urllib.parse import urlencode, parse_qsl, urlparse, urlunparse

import requests

from core.models import WebFinding, WebVulnType
from providers.base import BaseProvider
from web.crawler import CrawlResult, PageAsset
from web.fingerprinter import SiteFingerprint
from web.ai_probe_advisor import AIProbeAdvisor

# Import payload catalogs
from web.payloads import sqli, xss, ssrf, lfi, open_redirect, header_injection

logger = logging.getLogger(__name__)

# Payload mapping for dynamic lookup
PAYLOAD_CATALOG = {
    "SQLi": sqli.CONTEXTS,
    "XSS": xss.CONTEXTS,
    "SSRF": ssrf.CONTEXTS,
    "LFI": lfi.CONTEXTS,
    "OpenRedirect": open_redirect.CONTEXTS,
    "HeaderInjection": header_injection.CONTEXTS,
}

# Common parameter names to fuzz when a page has no visible params
FUZZ_PARAM_NAMES: list[str] = [
    "id", "q", "search", "query", "name", "user", "username",
    "file", "path", "page", "url", "redirect", "next", "return",
    "callback", "input", "cmd", "data", "key", "value", "ref",
    "lang", "type", "action", "token", "email", "sort", "order",
    "category", "item", "product", "view", "template", "include",
    "target", "dest", "destination", "redir", "continue", "go",
]

# ── Probe Engine ──────────────────────────────────────────────────────────────

class ProbeAbortedError(Exception):
    """Raised when the probe engine must stop immediately."""
    pass


class ProbeEngine:
    """Orchestrates active payload delivery against discovered parameters."""

    def __init__(
        self,
        provider: BaseProvider,
        fingerprint: SiteFingerprint,
        request_delay: float = 0.5,
        max_workers: int = 4,
        timeout: int = 15,
        max_payloads_per_param: int = 5
    ) -> None:
        self.advisor = AIProbeAdvisor(provider)
        self.provider = provider
        self.fingerprint = fingerprint
        self.request_delay = request_delay
        self.max_workers = max_workers
        self.timeout = timeout
        self.max_payloads_per_param = max_payloads_per_param

        self._session = requests.Session()
        self._session.headers.update({"User-Agent": "RavenScanner/1.0 (Active Test)"})

        # Concurrency & Safety Controls
        self._findings: list[WebFinding] = []
        self._findings_lock = threading.Lock()

        # Rate limiting
        self._go_flag = threading.Event()
        self._go_flag.set()

        self._rate_limit_lock = threading.Lock()
        self._tokens = 60.0
        self._last_token_update = time.monotonic()

        # Abort tracking
        self._consecutive_errors = 0
        self._error_lock = threading.Lock()

        # Deduplication
        self._seen_findings: set[str] = set()

    # ── Rate Limiting ─────────────────────────────────────────────────────────

    def _wait_for_token(self) -> None:
        """Blocks until a rate limit token is available (max 60/min = 1/sec)."""
        while True:
            self._go_flag.wait()
            with self._rate_limit_lock:
                now = time.monotonic()
                elapsed = now - self._last_token_update
                self._tokens = min(60.0, self._tokens + elapsed)
                self._last_token_update = now
                if self._tokens >= 1.0:
                    self._tokens -= 1.0
                    return
            time.sleep(0.1)

    def _handle_429(self) -> None:
        """Pauses all threads for 30 seconds when HTTP 429 is received."""
        if self._go_flag.is_set():
            logger.warning("HTTP 429 received. Pausing active probing for 30 seconds.")
            self._go_flag.clear()
            time.sleep(30)
            logger.info("Resuming active probing.")
            self._go_flag.set()

    # ── Core Probing Logic ────────────────────────────────────────────────────

    def probe_all(self, crawl_result: CrawlResult) -> list[WebFinding]:
        """Main entry. Emits passive findings, then probes all injection points."""
        logger.info(f"Starting active probing with {self.max_workers} workers.")

        # Phase 0: Emit passive findings from fingerprint data
        self._emit_passive_findings(crawl_result)

        # Phase 1: Build task list from crawled parameters + synthetic fuzzing
        tasks = self._generate_tasks(crawl_result)

        logger.info(f"Generated {len(tasks)} injection tasks.")

        # Phase 2: Execute probing tasks
        for task in tasks:
            try:
                self._process_task(*task)
            except ProbeAbortedError as e:
                logger.error(f"Active probing aborted: {e}")
                break

        return self._findings

    def _generate_tasks(self, crawl_result: CrawlResult) -> list[tuple]:
        """Build the full list of (url, method, parameter, injection_point, context) tasks."""
        tasks: list[tuple] = []
        pages_with_params: set[str] = set()

        for page in crawl_result.pages:
            # Explicit query parameters from crawled URLs
            for param in page.query_params:
                if self._is_safe_to_probe(param):
                    tasks.append((page.url, page.method, param, "query", "Query string parameter"))
                    pages_with_params.add(page.url)

            # Form fields
            for form in page.forms:
                for field in form.fields:
                    if self._is_safe_to_probe(field.name):
                        tasks.append((form.action, form.method, field.name, "body", f"Form {field.field_type} field"))
                        pages_with_params.add(page.url)

            # Path segment fuzzing — look for numeric/alphanumeric segments in the URL
            path_tasks = self._extract_path_params(page)
            tasks.extend(path_tasks)
            if path_tasks:
                pages_with_params.add(page.url)

        # Synthetic parameter fuzzing for pages with NO params
        for page in crawl_result.pages:
            if page.url not in pages_with_params:
                # Try the most common injectable param names
                for param_name in FUZZ_PARAM_NAMES[:15]:
                    tasks.append((page.url, "GET", param_name, "query", f"Fuzzed parameter (no params on page)"))

        return tasks

    def _extract_path_params(self, page: PageAsset) -> list[tuple]:
        """Extract potential path-based parameters from REST-style URLs."""
        tasks: list[tuple] = []
        parsed = urlparse(page.url)
        segments = [s for s in parsed.path.split("/") if s]

        for i, seg in enumerate(segments):
            # Numeric IDs or short alphanumeric tokens are likely parameters
            if re.match(r'^\d+$', seg) or (len(seg) <= 36 and re.match(r'^[a-f0-9\-]+$', seg, re.I) and len(seg) >= 4):
                tasks.append((page.url, "GET", f"__path_segment_{i}:{seg}", "path",
                              f"Path segment '{seg}' at position {i}"))

        return tasks

    def _is_safe_to_probe(self, param_name: str) -> bool:
        """MANDATORY Safety control: Never probe CSRF tokens."""
        unsafe_names = {"csrf_token", "_token", "authenticity_token", "__requestverificationtoken"}
        return param_name.lower() not in unsafe_names

    def _process_task(
        self,
        url: str,
        method: str,
        parameter: str,
        injection_point: Literal["query", "body", "header", "path"],
        param_context: str
    ) -> None:
        """Probes a single parameter across AI-selected payload types."""
        # 1. Get baseline (average of 2 requests)
        times = []
        for _ in range(2):
            _, _, _, t_ms = self._send_probe(url, method, parameter, "raven_baseline_test", injection_point)
            times.append(t_ms)
        baseline_time_ms = max(sum(times) / 2.0, 1.0)  # floor at 1ms to avoid division issues

        # 2. Ask AI advisor which vuln types to test
        vuln_types = self.advisor.select_payloads_for_target(url, parameter, param_context, self.fingerprint)

        for v_type in vuln_types:
            contexts = PAYLOAD_CATALOG.get(v_type, [])
            selected = contexts[:self.max_payloads_per_param]

            for ctx in selected:
                # 3. Send Probe
                status, headers, body_snippet, resp_time = self._send_probe(
                    url, method, parameter, ctx.payload, injection_point
                )

                if status == 429:
                    self._handle_429()
                    continue

                if status == 0:
                    continue  # Connection error

                # 4. Pre-filter: determine if the response warrants AI analysis
                should_analyze = False

                if ctx.expected_indicator.startswith("TIME_DELAY"):
                    # Time-based blind check: > 4x baseline AND > 4000ms
                    if resp_time > 4 * baseline_time_ms and resp_time > 4000:
                        should_analyze = True

                elif ctx.expected_indicator in ("BOOLEAN_TRUE", "BOOLEAN_FALSE"):
                    # Boolean blind — handled separately below
                    continue

                else:
                    # String-match pre-filter: check body AND headers
                    indicator = ctx.expected_indicator.lower()
                    body_lower = body_snippet.lower()
                    headers_str = str(headers).lower()

                    # Standard body/header match
                    if indicator in body_lower or indicator in headers_str:
                        should_analyze = True

                    # Open redirect: check Location header specifically for 3xx responses
                    if v_type == "OpenRedirect" and status in (301, 302, 303, 307, 308):
                        location = headers.get("Location", "") or headers.get("location", "")
                        if indicator in location.lower():
                            should_analyze = True

                    # Error-based SQLi: check against the full error indicator list
                    if v_type == "SQLi" and not should_analyze:
                        for err in sqli.ERROR_INDICATORS:
                            if err in body_lower:
                                should_analyze = True
                                break

                if not should_analyze:
                    continue

                # 5. Ask AI advisor to analyze
                analysis = self.advisor.analyze_probe_response(
                    url=url,
                    parameter=parameter,
                    payload_sent=ctx.payload,
                    vulnerability_type=v_type,
                    response_status=status,
                    response_headers=headers,
                    response_body_snippet=body_snippet,
                    response_time_ms=resp_time,
                    baseline_response_time_ms=baseline_time_ms
                )

                # 6. Record finding if confirmed
                if analysis and analysis.confirmed:
                    self._add_finding(
                        v_type=v_type,
                        severity=ctx.severity,
                        url=url,
                        method=method,
                        parameter=parameter,
                        payload=ctx.payload,
                        evidence=analysis.evidence_snippet,
                        status=status,
                        ai_analysis=analysis.explanation,
                        remediation=analysis.remediation,
                        curl_poc=analysis.curl_poc or self._build_curl_poc(url, method, parameter, ctx.payload, injection_point),
                    )
                    return  # Stop testing this parameter

            # After processing a vuln type, try boolean blind if it's SQLi
            if v_type == "SQLi":
                self._test_boolean_blind(url, method, parameter, injection_point, baseline_time_ms)

    # ── Boolean Blind SQLi ────────────────────────────────────────────────────

    def _test_boolean_blind(
        self, url: str, method: str, parameter: str,
        injection_point: str, baseline_time_ms: float
    ) -> None:
        """Comparative analysis: send TRUE and FALSE payloads, compare responses."""
        true_payload = "' AND '1'='1"
        false_payload = "' AND '1'='2"

        s1, h1, body1, t1 = self._send_probe(url, method, parameter, true_payload, injection_point)
        s2, h2, body2, t2 = self._send_probe(url, method, parameter, false_payload, injection_point)

        if s1 == 0 or s2 == 0:
            return  # Connection errors

        # Compare: different status codes, or significant body length difference
        status_differs = s1 != s2
        len1, len2 = len(body1), len(body2)
        length_ratio = abs(len1 - len2) / max(len1, len2, 1)
        length_differs = length_ratio > 0.10 and abs(len1 - len2) > 50

        if not (status_differs or length_differs):
            return  # Responses are too similar

        # Forward to AI for confirmation
        combined_context = (
            f"BOOLEAN BLIND SQLi COMPARISON:\n"
            f"TRUE payload: {true_payload}\n"
            f"TRUE response: HTTP {s1}, {len1} bytes, {t1:.0f}ms\n"
            f"TRUE body (first 500): {body1[:500]}\n\n"
            f"FALSE payload: {false_payload}\n"
            f"FALSE response: HTTP {s2}, {len2} bytes, {t2:.0f}ms\n"
            f"FALSE body (first 500): {body2[:500]}\n\n"
            f"Status differs: {status_differs}, Length ratio: {length_ratio:.2%}"
        )

        analysis = self.advisor.analyze_probe_response(
            url=url,
            parameter=parameter,
            payload_sent=f"TRUE: {true_payload} / FALSE: {false_payload}",
            vulnerability_type="SQLi",
            response_status=s1,
            response_headers=h1,
            response_body_snippet=combined_context,
            response_time_ms=t1,
            baseline_response_time_ms=baseline_time_ms
        )

        if analysis and analysis.confirmed:
            self._add_finding(
                v_type="SQLi",
                severity="High",
                url=url,
                method=method,
                parameter=parameter,
                payload=f"Boolean Blind: TRUE={true_payload}, FALSE={false_payload}",
                evidence=f"TRUE: HTTP {s1} ({len1}B), FALSE: HTTP {s2} ({len2}B). Diff={length_ratio:.0%}",
                status=s1,
                ai_analysis=analysis.explanation,
                remediation=analysis.remediation,
                curl_poc=analysis.curl_poc or self._build_curl_poc(url, method, parameter, true_payload, injection_point),
            )

    # ── Passive Findings from Fingerprint ──────────────────────────────────────

    def _emit_passive_findings(self, crawl_result: CrawlResult) -> None:
        """Convert fingerprint data into WebFinding objects."""
        fp = self.fingerprint
        base_url = crawl_result.base_url

        # Missing security headers
        if fp.missing_security_headers:
            critical_headers = {"Strict-Transport-Security", "Content-Security-Policy"}
            missing_critical = [h for h in fp.missing_security_headers if h in critical_headers]
            severity = "Medium" if missing_critical else "Low"

            self._add_finding(
                v_type="MissingSecurityHeaders",
                severity=severity,
                url=base_url,
                method="GET",
                parameter="HTTP Headers",
                payload="",
                evidence=f"Missing headers: {', '.join(fp.missing_security_headers)}",
                status=200,
                ai_analysis=f"The application is missing {len(fp.missing_security_headers)} security headers: {', '.join(fp.missing_security_headers)}. "
                            f"This leaves the application vulnerable to clickjacking (X-Frame-Options), "
                            f"MIME sniffing (X-Content-Type-Options), and cross-site attacks (CSP).",
                remediation="Add the following headers via middleware or reverse proxy configuration: "
                            + ", ".join(fp.missing_security_headers),
                curl_poc=f"curl -I '{base_url}'",
            )

        # Exposed interesting paths
        for path_entry in fp.interesting_paths:
            # Parse "/.git/HEAD [200]" format
            parts = path_entry.rsplit(" ", 1)
            path = parts[0]
            status_str = parts[1].strip("[]") if len(parts) > 1 else "200"

            # Determine severity based on path
            if any(p in path for p in [".git", ".env", "wp-config", "config.php", "parameters.yml"]):
                severity = "Critical"
                vuln_type = "SensitiveFileExposure"
                analysis = f"The file {path} is publicly accessible. This can expose source code, credentials, API keys, and database passwords."
            elif any(p in path for p in ["/admin", "/console", "/actuator/env", "/debug"]):
                severity = "High"
                vuln_type = "AdminPanelExposed"
                analysis = f"Administrative interface at {path} is accessible. This may allow unauthorized configuration changes or code execution."
            elif any(p in path for p in ["/swagger", "/api-docs", "/graphql"]):
                severity = "Medium"
                vuln_type = "APIDocumentationExposed"
                analysis = f"API documentation at {path} is publicly accessible. This reveals all endpoints, parameters, and data schemas to attackers."
            else:
                severity = "Low"
                vuln_type = "InformationDisclosure"
                analysis = f"Interesting path {path} is accessible (HTTP {status_str})."

            parsed = urlparse(base_url)
            full_url = f"{parsed.scheme}://{parsed.netloc}{path}"

            self._add_finding(
                v_type=vuln_type,
                severity=severity,
                url=full_url,
                method="GET",
                parameter="Path",
                payload="",
                evidence=f"{path} returned HTTP {status_str}",
                status=int(status_str) if status_str.isdigit() else 200,
                ai_analysis=analysis,
                remediation=f"Block access to {path} via web server configuration or .htaccess rules. "
                            f"For .git/.env files, add deny rules in nginx/Apache config.",
                curl_poc=f"curl '{full_url}'",
            )

        # Insecure cookies
        for cookie in fp.cookies:
            issues = []
            if not cookie.has_httponly:
                issues.append("Missing HttpOnly (accessible via JavaScript/XSS)")
            if not cookie.has_secure:
                issues.append("Missing Secure flag (sent over HTTP)")
            if not cookie.has_samesite:
                issues.append("Missing SameSite attribute (CSRF vulnerable)")

            if issues:
                self._add_finding(
                    v_type="InsecureCookie",
                    severity="Medium",
                    url=base_url,
                    method="GET",
                    parameter=f"Cookie: {cookie.name}",
                    payload="",
                    evidence=f"Cookie '{cookie.name}': {'; '.join(issues)}",
                    status=200,
                    ai_analysis=f"The cookie '{cookie.name}' has {len(issues)} security issue(s): {'; '.join(issues)}. "
                                f"This can lead to session hijacking via XSS or interception over unencrypted connections.",
                    remediation=f"Set HttpOnly, Secure, and SameSite=Lax on the '{cookie.name}' cookie.",
                    curl_poc=f"curl -I '{base_url}'",
                )

        # Information disclosures
        for disclosure in fp.information_disclosures:
            self._add_finding(
                v_type="InformationDisclosure",
                severity="High" if "stack trace" in disclosure.lower() or "debug" in disclosure.lower() else "Medium",
                url=base_url,
                method="GET",
                parameter="Response Body",
                payload="",
                evidence=disclosure,
                status=200,
                ai_analysis=f"The application exposes sensitive information: {disclosure}. "
                            f"This reveals internal implementation details useful for targeted attacks.",
                remediation="Disable debug mode in production. Implement custom error pages that don't expose stack traces or internal details.",
                curl_poc=f"curl '{base_url}'",
            )

        # TLS check
        if fp.tls_info.get("scheme") == "HTTP":
            self._add_finding(
                v_type="NoTLS",
                severity="Medium",
                url=base_url,
                method="GET",
                parameter="Protocol",
                payload="",
                evidence="Site is served over HTTP without TLS encryption",
                status=200,
                ai_analysis="The application does not use TLS/HTTPS. All traffic including credentials, "
                            "session tokens, and sensitive data is transmitted in plaintext.",
                remediation="Enable TLS/HTTPS. Obtain a certificate from Let's Encrypt (free) and configure HSTS.",
                curl_poc=f"curl -I '{base_url}'",
            )

    # ── Finding Helper ────────────────────────────────────────────────────────

    def _add_finding(self, *, v_type: str, severity: str, url: str, method: str,
                     parameter: str, payload: str, evidence: str, status: int,
                     ai_analysis: str, remediation: str, curl_poc: str) -> None:
        """Add a finding with deduplication."""
        dedup_key = f"{v_type}|{url}|{parameter}"
        if dedup_key in self._seen_findings:
            return
        self._seen_findings.add(dedup_key)

        finding_id = f"WEB-{len(self._findings) + 1:03d}"
        finding = WebFinding(
            finding_id=finding_id,
            vulnerability_type=v_type,
            severity=severity,
            url=url,
            method=method,
            parameter=parameter,
            payload_sent=payload,
            evidence=evidence,
            http_status=status,
            confirmed=True,
            ai_analysis=ai_analysis,
            remediation=remediation,
            curl_poc=curl_poc,
        )
        with self._findings_lock:
            self._findings.append(finding)

    # ── Probe Sending ─────────────────────────────────────────────────────────

    def _send_probe(
        self,
        url: str,
        method: str,
        parameter: str,
        payload: str,
        injection_point: str
    ) -> tuple[int, dict, str, float]:
        """Sends a single probe request, handling rate limits and timeouts."""
        self._wait_for_token()

        parsed = urlparse(url)
        params = parse_qsl(parsed.query, keep_blank_values=True)

        data = None
        target_url = url
        extra_headers: dict[str, str] = {}

        if injection_point == "query":
            # FIX #1: If parameter exists, replace it. If not, APPEND it.
            existing_keys = {k for k, v in params}
            if parameter in existing_keys:
                new_params = [(k, payload if k == parameter else v) for k, v in params]
            else:
                new_params = list(params) + [(parameter, payload)]
            target_url = urlunparse(parsed._replace(query=urlencode(new_params)))

        elif injection_point == "body" and method.upper() in ("POST", "PUT"):
            data = {parameter: payload}

        elif injection_point == "header":
            # FIX #3: Actually inject payloads as HTTP headers
            # Use the header_injection HEADER_TARGETS for structured injection
            if ":" in parameter:
                header_name, _ = parameter.split(":", 1)
                extra_headers[header_name.strip()] = payload
            else:
                extra_headers[parameter] = payload

        elif injection_point == "path":
            # FIX #8: Path segment injection
            if parameter.startswith("__path_segment_"):
                # Extract segment index and original value
                meta = parameter.replace("__path_segment_", "")
                idx_str, original = meta.split(":", 1)
                idx = int(idx_str)
                segments = parsed.path.split("/")
                # Replace the segment at the given index (+1 because split creates empty first element)
                real_idx = idx + 1 if segments and segments[0] == "" else idx
                if real_idx < len(segments):
                    segments[real_idx] = payload
                    new_path = "/".join(segments)
                    target_url = urlunparse(parsed._replace(path=new_path))

        start_time = time.monotonic()
        try:
            resp = self._session.request(
                method=method,
                url=target_url,
                data=data,
                headers=extra_headers if extra_headers else None,
                timeout=self.timeout,
                allow_redirects=False
            )
            elapsed_ms = (time.monotonic() - start_time) * 1000

            with self._error_lock:
                self._consecutive_errors = 0

            return (resp.status_code, dict(resp.headers), resp.text[:3000], elapsed_ms)

        except requests.RequestException as e:
            elapsed_ms = (time.monotonic() - start_time) * 1000

            with self._error_lock:
                self._consecutive_errors += 1
                if self._consecutive_errors >= 5:
                    raise ProbeAbortedError(f"5 consecutive connection errors. Last error: {e}")

            return (0, {}, "", elapsed_ms)

    def _build_curl_poc(
        self,
        url: str,
        method: str,
        parameter: str,
        payload: str,
        injection_point: str
    ) -> str:
        """Generates a copy-paste curl command."""
        if injection_point == "query":
            parsed = urlparse(url)
            params = parse_qsl(parsed.query, keep_blank_values=True)
            existing_keys = {k for k, v in params}
            if parameter in existing_keys:
                new_params = [(k, payload if k == parameter else v) for k, v in params]
            else:
                new_params = list(params) + [(parameter, payload)]
            target_url = urlunparse(parsed._replace(query=urlencode(new_params)))
            return f"curl -X {method} '{target_url}'"
        elif injection_point == "header":
            return f"curl -H '{parameter}: {payload}' '{url}'"
        elif injection_point == "path":
            return f"curl '{url}'  # with path segment replaced by: {payload}"
        return f"curl -X {method} '{url}' -d '{parameter}={payload}'"
