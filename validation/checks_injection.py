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

from typing import Any, Dict

from core.injection_signals import sql_signals, ssrf_signals, xss_signals
from core.models import Confidence, Evidence, Finding, FindingStatus
from validation.outcome import conclude


def _sql_evidence(url: str, parameter: str, data: Dict[str, Any], note: str) -> Evidence:
    tests = data.get("tests", {})
    s = sql_signals(tests)
    return Evidence(
        kind="tool_output", source_tool="sql_injection_probe", summary=note,
        data={"url": url, "parameter": parameter, "test_inputs": "benign baseline x2, single-quote, "
              "boolean-true (OR 1=1), boolean-false (AND 1=2) -- all read-only",
              "status_by_test": {k: v.get("status_code") for k, v in tests.items()},
              "length_by_test": {k: len(v.get("body", "") or "") for k, v in tests.items()},
              "sql_error_signature_by_test": {k: v.get("sql_error_signature") for k, v in tests.items()},
              "baseline_jitter_bytes": s["jitter"],
              "error_based": s["error_based"], "boolean_based": s["boolean_based"]})


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
        s0, s1 = sql_signals(runs[0].get("tests", {})), sql_signals(runs[1].get("tests", {}))
        e0, b0 = s0["error_based"], s0["boolean_based"]
        e1, b1 = s1["error_based"], s1["boolean_based"]
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
        s = xss_signals(d)
        ev = [Evidence(kind="tool_output", source_tool="xss_probe",
                       summary=f"Independent re-test with a fresh canary token (context: {s['context']}).",
                       data={"url": url, "parameter": parameter, "method": method, "location": location,
                             "test_input": "one unique, non-persisted reflected canary marker",
                             "context": s["context"], "marker_reflected": d.get("marker_reflected"),
                             "tag_breakout": d.get("tag_breakout"), "escaped": d.get("escaped")})]
        if not d.get("marker_reflected"):
            return conclude(f, FindingStatus.REJECTED, Confidence.NONE,
                            "The payload was not reflected on independent re-test.", "reflected_xss", ev)
        if d.get("escaped"):
            return conclude(f, FindingStatus.REJECTED, Confidence.NONE,
                            "The payload is reflected but HTML-escaped; this is reflection, not executable XSS.",
                            "reflected_xss", ev)
        if s["executable"]:
            return conclude(f, FindingStatus.CONFIRMED, Confidence.HIGH,
                            "An unescaped injected metacharacter breaks out at the reflection site in an "
                            f"executable {s['context'].replace('_', ' ')} context on independent re-test.",
                            "reflected_xss", ev)
        return conclude(f, FindingStatus.INCONCLUSIVE, Confidence.LOW,
                        "The marker is reflected unescaped but no injected metacharacter breaks out of its "
                        "context, so executability could not be confirmed.", "reflected_xss", ev)

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
        s = ssrf_signals(d)
        ev = [Evidence(kind="tool_output", source_tool="ssrf_probe",
                       summary="Independent re-test with a fresh, unique callback token.",
                       data={"url": url, "parameter": parameter, "method": method, "location": location,
                             "test_input": "a Raven-hosted loopback callback URL carrying a unique token",
                             "callback_available": d.get("callback_available", True),
                             "callback_received": d.get("callback_received"),
                             "application_accepted": d.get("application_accepted")})]
        if s["state"] == "callback_received":
            return conclude(f, FindingStatus.CONFIRMED, Confidence.HIGH,
                            "Raven's callback canary independently received a connection carrying a fresh unique "
                            "token after the parameter was set to its URL: the server actually performed the "
                            "request.", "ssrf", ev)
        if s["state"] == "mechanism_unavailable":
            return conclude(f, FindingStatus.INCONCLUSIVE, Confidence.LOW,
                            "SSRF could not be tested: Raven's loopback callback listener was unavailable this "
                            "run. This is not evidence of absence.", "ssrf", ev)
        if s["state"] == "accepted_no_callback":
            return conclude(f, FindingStatus.INCONCLUSIVE, Confidence.LOW, s["why"], "ssrf", ev)
        return conclude(f, FindingStatus.REJECTED, Confidence.NONE,
                        "The application neither accepted the supplied URL nor triggered the callback on "
                        "independent re-test.", "ssrf", ev)
