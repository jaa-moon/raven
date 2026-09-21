"""
validation/checks_injection.py
-------------------------------
Independent verification for active-injection candidates. Every check makes
its OWN fresh probe(s) through the gateway -- the `injection.*.validate`
capability, never the agent's already-collected result -- and requires the
interesting behavior to repeat before confirming anything. A single
HTTP 500/200/length delta is never, by itself, treated as proof.
"""

from __future__ import annotations

from typing import Any, Dict, Tuple

from core.models import Confidence, Evidence, Finding, FindingStatus
from validation.outcome import conclude


def _sql_signal(data: Dict[str, Any]) -> Tuple[bool, bool]:
    tests = data.get("tests", {})
    base, quote = tests.get("baseline", {}), tests.get("quote", {})
    true_r, false_r = tests.get("true", {}), tests.get("false", {})
    error_based = bool(quote.get("sql_error_signature") or true_r.get("sql_error_signature")
                       or false_r.get("sql_error_signature"))
    b_status, t_status, f_status = base.get("status_code"), true_r.get("status_code"), false_r.get("status_code")
    b_len = len(base.get("body", "") or "")
    t_len, f_len = len(true_r.get("body", "") or ""), len(false_r.get("body", "") or "")
    boolean_based = bool(
        t_status == b_status and abs(t_len - b_len) < max(20, b_len * 0.05)
        and (f_status != b_status or abs(f_len - b_len) > max(40, b_len * 0.1)))
    return error_based, boolean_based


def _sql_evidence(url: str, parameter: str, data: Dict[str, Any], note: str) -> Evidence:
    tests = data.get("tests", {})
    return Evidence(
        kind="tool_output", source_tool="sql_injection_probe", summary=note,
        data={"url": url, "parameter": parameter,
              "status_by_test": {k: v.get("status_code") for k, v in tests.items()},
              "length_by_test": {k: len(v.get("body", "") or "") for k, v in tests.items()},
              "sql_error_signature_by_test": {k: v.get("sql_error_signature") for k, v in tests.items()}})


class InjectionChecks:
    async def _v_sql_injection(self, f: Finding) -> Finding:  # type: ignore[misc]
        sig = f.signal
        url, parameter = sig["url"], sig["parameter"]
        method, location = sig.get("method", "GET"), sig.get("location", "query")
        runs = []
        for i in range(2):                                     # repeatability, never a one-shot verdict
            res = await self.ctx.call(
                "injection.sql.validate", {"url": url, "parameter": parameter, "method": method, "location": location},
                f"Re-test SQL injection on '{parameter}' (independent re-run {i + 1}/2)")
            if not res.ok:
                return conclude(f, FindingStatus.INCONCLUSIVE, Confidence.LOW,
                                f"Could not re-run the SQL injection probe: {res.error}", "sql_injection")
            runs.append(res.data)

        ev = [_sql_evidence(url, parameter, runs[0], "First independent re-test."),
              _sql_evidence(url, parameter, runs[1], "Second independent re-test (repeatability check).")]
        e0, b0 = _sql_signal(runs[0])
        e1, b1 = _sql_signal(runs[1])
        if e0 and e1:
            return conclude(f, FindingStatus.CONFIRMED, Confidence.HIGH,
                            "A single quote reproducibly triggers a database-error signature across two "
                            "independent re-tests.", "sql_injection", ev)
        if b0 and b1:
            return conclude(f, FindingStatus.CONFIRMED, Confidence.MEDIUM,
                            "Boolean-true and boolean-false payloads reproducibly diverge (boolean-true matches "
                            "the benign baseline, boolean-false does not) across two independent re-tests -- a "
                            "blind/boolean-based SQL injection pattern.", "sql_injection", ev)
        if e0 or e1 or b0 or b1:
            return conclude(f, FindingStatus.INCONCLUSIVE, Confidence.LOW,
                            "The candidate behavior did not repeat consistently across independent re-tests; "
                            "HTTP status/length variance alone is not proof of SQL injection.", "sql_injection", ev)
        return conclude(f, FindingStatus.REJECTED, Confidence.NONE,
                        "Independent re-testing found no error signature and no consistent boolean divergence.",
                        "sql_injection", ev)

    async def _v_reflected_xss(self, f: Finding) -> Finding:  # type: ignore[misc]
        sig = f.signal
        url, parameter = sig["url"], sig["parameter"]
        method, location = sig.get("method", "GET"), sig.get("location", "query")
        res = await self.ctx.call(
            "injection.xss.validate", {"url": url, "parameter": parameter, "method": method, "location": location},
            f"Re-test reflected XSS on '{parameter}' with a fresh canary token")
        if not res.ok:
            return conclude(f, FindingStatus.INCONCLUSIVE, Confidence.LOW,
                            f"Could not re-run the XSS probe: {res.error}", "reflected_xss")
        d = res.data
        ev = [Evidence(kind="tool_output", source_tool="xss_probe",
                       summary=f"Independent re-test with a fresh canary token (context: {d.get('context')}).",
                       data={"url": url, "parameter": parameter, "context": d.get("context"),
                             "marker_reflected": d.get("marker_reflected"), "escaped": d.get("escaped")})]
        if not d.get("marker_reflected"):
            return conclude(f, FindingStatus.REJECTED, Confidence.NONE,
                            "The payload was not reflected on independent re-test.", "reflected_xss", ev)
        if d.get("escaped"):
            return conclude(f, FindingStatus.REJECTED, Confidence.NONE,
                            "The payload is reflected but HTML-escaped; this is reflection, not executable XSS.",
                            "reflected_xss", ev)
        if d.get("context") in ("html_body", "html_attribute", "javascript"):
            return conclude(f, FindingStatus.CONFIRMED, Confidence.HIGH,
                            "An unescaped, attacker-controlled marker is reflected in an executable "
                            f"{str(d.get('context')).replace('_', ' ')} context on independent re-test.",
                            "reflected_xss", ev)
        return conclude(f, FindingStatus.INCONCLUSIVE, Confidence.LOW,
                        "The marker is reflected unescaped but its context could not be classified as executable.",
                        "reflected_xss", ev)

    async def _v_ssrf(self, f: Finding) -> Finding:  # type: ignore[misc]
        sig = f.signal
        url, parameter = sig["url"], sig["parameter"]
        method, location = sig.get("method", "GET"), sig.get("location", "query")
        res = await self.ctx.call(
            "injection.ssrf.validate", {"url": url, "parameter": parameter, "method": method, "location": location},
            f"Re-test SSRF on '{parameter}' with a fresh callback token")
        if not res.ok:
            return conclude(f, FindingStatus.INCONCLUSIVE, Confidence.LOW,
                            f"Could not re-run the SSRF probe: {res.error}", "ssrf")
        d = res.data
        ev = [Evidence(kind="tool_output", source_tool="ssrf_probe",
                       summary="Independent re-test with a fresh callback token.",
                       data={"url": url, "parameter": parameter, "callback_received": d.get("callback_received"),
                             "application_accepted": d.get("application_accepted")})]
        if d.get("callback_received"):
            return conclude(f, FindingStatus.CONFIRMED, Confidence.HIGH,
                            "Raven's callback canary independently received a connection after the parameter was "
                            "set to its URL, on a fresh token: the server actually performed the request.",
                            "ssrf", ev)
        if d.get("application_accepted"):
            return conclude(f, FindingStatus.INCONCLUSIVE, Confidence.LOW,
                            "The application accepted the supplied URL without an immediate rejection, but the "
                            "callback was never reached; this shows acceptance, not a confirmed server-side "
                            "request (the target may be unable to reach Raven's loopback callback, e.g. across a "
                            "network boundary).", "ssrf", ev)
        return conclude(f, FindingStatus.REJECTED, Confidence.NONE,
                        "The application neither accepted the supplied URL nor triggered the callback on "
                        "independent re-test.", "ssrf", ev)
