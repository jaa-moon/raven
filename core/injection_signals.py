"""
core/injection_signals.py
-------------------------
Pure, side-effect-free interpretation of a controlled injection probe's raw
observations. This is the single place that decides *what a probe result
means*; it performs no I/O and reaches for no tool.

It is deliberately shared by both:

    agents/injection.py            -- cheap agent-side triage: "raise a candidate?"
    validation/checks_injection.py -- the independent verdict, over the validator's
                                      OWN fresh probe(s).

Sharing the *math* does not weaken independence: the two callers still feed it
observations from separate, independent probe rounds. What it removes is the
risk of the two thresholds silently drifting apart. No function here ever
confirms a finding on a single, unrepeated signal, and none treats a bare
HTTP 500, a length change, or a timing difference as proof on its own.
"""

from __future__ import annotations

from typing import Any, Dict, Optional

# Length tolerances used when the target exposes no natural jitter. A response
# whose measured jitter is larger than these takes over instead (see below), so
# these are floors, not fixed thresholds.
_MATCH_FLOOR = 24        # "behaves like the baseline" tolerance, in bytes
_DIVERGE_FLOOR = 32      # "meaningfully different from the baseline" threshold


def _len(entry: Any) -> int:
    return len((entry or {}).get("body", "") or "") if isinstance(entry, dict) else 0


def _status(entry: Any) -> Optional[int]:
    return entry.get("status_code") if isinstance(entry, dict) else None


def _err(entry: Any) -> bool:
    return bool(entry.get("sql_error_signature")) if isinstance(entry, dict) else False


def redact_probe_data(kind: str, data: Dict[str, Any]) -> Dict[str, Any]:
    """A body-free digest of a probe round, safe to persist in a candidate's
    signal and hypothesis trail.

    Raw HTTP response bodies can be large and may contain sensitive application
    content, so they are never carried into stored state; for SQL only per-test
    status, length and error-signature survive. XSS/SSRF probe outputs already
    contain no response body (only Raven's own canary and boolean flags)."""
    if kind == "sql_injection":
        tests = data.get("tests", {})
        digest = {
            name: {"status_code": t.get("status_code"), "length": len(t.get("body", "") or ""),
                   "sql_error_signature": t.get("sql_error_signature"),
                   **({"error": t["error"]} if "error" in t else {})}
            for name, t in tests.items() if isinstance(t, dict)
        }
        return {"parameter": data.get("parameter"), "location": data.get("location"),
                "method": data.get("method"), "tests": digest}
    return {k: v for k, v in data.items() if k != "body"}


def baseline_jitter(tests: Dict[str, Any]) -> int:
    """Natural byte-length variation between two identical benign requests.

    When the target sends a second baseline (``baseline2``), the difference
    between the two benign responses is the noise floor that any 'divergence'
    must clear to count. Without it, jitter is unknown and treated as 0 (the
    floors below then apply)."""
    b1, b2 = tests.get("baseline"), tests.get("baseline2")
    if not isinstance(b1, dict) or not isinstance(b2, dict):
        return 0
    if _status(b1) != _status(b2):
        return _DIVERGE_FLOOR  # unstable even for identical input: demand a lot
    return abs(_len(b1) - _len(b2))


def sql_signals(tests: Dict[str, Any]) -> Dict[str, Any]:
    """Interpret one SQL probe round: (error_based, boolean_based) + why.

    * error_based   -- a database-error signature appears under a payload but
                       NOT in the benign baseline (so a page that always prints
                       a SQL-looking string cannot trigger it).
    * boolean_based -- the boolean-TRUE branch behaves like the baseline while
                       the boolean-FALSE branch diverges beyond the measured
                       jitter AND differs from the TRUE branch. Length/status
                       noise alone never qualifies.
    """
    base = tests.get("baseline", {})
    quote, true_r, false_r = tests.get("quote", {}), tests.get("true", {}), tests.get("false", {})

    base_err = _err(base) or _err(tests.get("baseline2", {}))
    error_based = (not base_err) and (_err(quote) or _err(true_r) or _err(false_r))

    jitter = baseline_jitter(tests)
    tol_match = max(jitter, _MATCH_FLOOR)
    tol_diverge = max(jitter * 3, _DIVERGE_FLOOR)

    b_status = _status(base)
    b_len, t_len, f_len = _len(base), _len(true_r), _len(false_r)

    true_like_baseline = _status(true_r) == b_status and abs(t_len - b_len) <= tol_match
    false_diverges = _status(false_r) != b_status or abs(f_len - b_len) > tol_diverge
    branches_differ = _status(true_r) != _status(false_r) or abs(t_len - f_len) > tol_diverge
    boolean_based = bool(true_like_baseline and false_diverges and branches_differ)

    if error_based:
        why = "A payload produced a database-error signature absent from the benign baseline."
    elif boolean_based:
        why = ("The boolean-true payload behaves like the benign baseline while the boolean-false "
               "payload diverges beyond the response's natural jitter, consistent with conditional "
               "query logic.")
    else:
        why = "Baseline, quote and boolean payloads produced equivalent responses (within jitter)."
    return {"error_based": error_based, "boolean_based": boolean_based, "jitter": jitter, "why": why}


def xss_signals(data: Dict[str, Any]) -> Dict[str, Any]:
    """Interpret one XSS probe round: is the reflection actually *executable*?

    'Executable' requires that an injected metacharacter survives unescaped at
    the reflection site (a real tag break-out), or that the raw payload lands
    in a JavaScript context. A marker that is merely present, or present but
    HTML-escaped, is reflection -- not XSS -- and is rejected.

    Backward-compatible: if the probe did not report ``tag_breakout`` (older or
    hand-built data), it falls back to the reflected context classification.
    """
    reflected = bool(data.get("marker_reflected"))
    escaped = bool(data.get("escaped"))
    context = data.get("context", "absent")
    if not reflected:
        return {"executable": False, "context": context, "why": "The injected marker was not reflected."}
    if escaped:
        return {"executable": False, "context": context,
                "why": "The injected marker is reflected but HTML-escaped; reflection, not executable XSS."}
    if "tag_breakout" in data:
        executable = bool(data.get("tag_breakout")) or (
            context == "javascript" and bool(data.get("raw_reflected")))
    else:
        executable = context in ("html_body", "html_attribute", "javascript")
    why = (f"An injected metacharacter survives unescaped in a {context.replace('_', ' ')} context."
           if executable else
           "The marker is reflected unescaped but no injected metacharacter breaks out of its context.")
    return {"executable": executable, "context": context, "why": why}


def ssrf_signals(data: Dict[str, Any]) -> Dict[str, Any]:
    """Interpret one SSRF probe round, distinguishing an unavailable callback
    mechanism from a callback that was simply never reached."""
    if not data.get("callback_available", True):
        return {"state": "mechanism_unavailable",
                "why": "Raven's loopback callback listener could not be started, so SSRF could not be tested."}
    if data.get("callback_received"):
        return {"state": "callback_received",
                "why": "The callback canary received a connection carrying this round's unique token: the "
                       "server performed the request."}
    if data.get("application_accepted"):
        return {"state": "accepted_no_callback",
                "why": "The application accepted the URL without an immediate rejection, but the callback was "
                       "never reached (acceptance is not a confirmed server-side request; the target may be "
                       "unable to reach Raven's loopback callback across a network boundary)."}
    return {"state": "rejected",
            "why": "The application neither accepted the supplied URL nor triggered the callback."}
