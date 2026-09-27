"""
Pure interpretation of probe observations (core.injection_signals). These are
the shared thresholds both the agent (candidate triage) and the validator
(verdict) use, so they are pinned directly and deterministically here.
"""

from __future__ import annotations

from core.injection_signals import (baseline_jitter, redact_probe_data, sql_signals,
                                     ssrf_signals, xss_signals)


def _body(n: int, seed: str = "x") -> dict:
    return {"status_code": 200, "body": seed * n, "sql_error_signature": False}


# ── SQL: jitter-aware boolean detection ────────────────────────────────────────

def test_error_signature_only_counts_when_absent_from_baseline():
    tests = {"baseline": _body(50), "baseline2": _body(50),
             "quote": {"status_code": 500, "body": "sql syntax error", "sql_error_signature": True},
             "true": _body(50), "false": _body(50)}
    assert sql_signals(tests)["error_based"] is True

    # A page that ALWAYS prints a SQL-looking string: the signature is in the
    # baseline too, so it is not evidence of injection.
    noisy = dict(tests)
    noisy["baseline"] = {"status_code": 200, "body": "sql syntax", "sql_error_signature": True}
    noisy["baseline2"] = dict(noisy["baseline"])
    assert sql_signals(noisy)["error_based"] is False


def test_boolean_divergence_within_natural_jitter_is_not_confirmed():
    """A page that varies its own length between two identical requests has high
    jitter; a true/false divergence smaller than that jitter is noise, not SQLi."""
    tests = {
        "baseline": _body(1000), "baseline2": _body(1300),   # 300 bytes of natural jitter
        "quote": _body(1000),
        "true": _body(1010),                                 # ~baseline
        "false": _body(1120),                                # differs, but < jitter
    }
    assert baseline_jitter(tests) == 300
    assert sql_signals(tests)["boolean_based"] is False


def test_boolean_divergence_beyond_jitter_is_flagged():
    tests = {
        "baseline": _body(1000), "baseline2": _body(1005),   # ~5 bytes jitter
        "quote": _body(1000),
        "true": _body(1000),                                 # matches baseline
        "false": _body(200),                                 # far below baseline
    }
    s = sql_signals(tests)
    assert s["boolean_based"] is True and s["error_based"] is False


def test_true_and_false_must_differ_from_each_other():
    """Both branches diverging from baseline the SAME way is not conditional logic."""
    tests = {"baseline": _body(1000), "baseline2": _body(1000),
             "quote": _body(1000), "true": _body(300), "false": _body(300)}
    assert sql_signals(tests)["boolean_based"] is False


# ── XSS: break-out vs mere reflection ──────────────────────────────────────────

def test_tag_breakout_in_html_body_is_executable():
    s = xss_signals({"marker_reflected": True, "escaped": False, "tag_breakout": True,
                     "raw_reflected": True, "context": "html_body"})
    assert s["executable"] is True


def test_escaped_reflection_is_not_executable_even_if_marker_present():
    s = xss_signals({"marker_reflected": True, "escaped": True, "tag_breakout": False,
                     "context": "html_attribute"})
    assert s["executable"] is False


def test_marker_without_tag_breakout_is_not_executable():
    s = xss_signals({"marker_reflected": True, "escaped": False, "tag_breakout": False,
                     "raw_reflected": False, "context": "html_body"})
    assert s["executable"] is False


def test_javascript_context_needs_raw_payload():
    assert xss_signals({"marker_reflected": True, "escaped": False, "tag_breakout": False,
                        "raw_reflected": True, "context": "javascript"})["executable"] is True
    assert xss_signals({"marker_reflected": True, "escaped": False, "tag_breakout": False,
                        "raw_reflected": False, "context": "javascript"})["executable"] is False


def test_legacy_data_without_tag_breakout_falls_back_to_context():
    # Hand-built/older data (no tag_breakout key) stays backward compatible.
    assert xss_signals({"marker_reflected": True, "escaped": False, "context": "html_body"})["executable"] is True


# ── SSRF: mechanism-unavailable is distinct from "not observed" ────────────────

def test_callback_received_is_confirmed_state():
    assert ssrf_signals({"callback_available": True, "callback_received": True})["state"] == "callback_received"


def test_callback_mechanism_unavailable_is_its_own_state():
    s = ssrf_signals({"callback_available": False, "callback_received": False})
    assert s["state"] == "mechanism_unavailable"


def test_accepted_without_callback_is_inconclusive_state():
    assert ssrf_signals({"callback_available": True, "callback_received": False,
                         "application_accepted": True})["state"] == "accepted_no_callback"


def test_rejected_when_neither_accepted_nor_called_back():
    assert ssrf_signals({"callback_available": True, "callback_received": False,
                         "application_accepted": False})["state"] == "rejected"


# ── Redaction: raw bodies never persisted ──────────────────────────────────────

def test_redaction_strips_sql_response_bodies_but_keeps_metrics():
    raw = {"parameter": "q", "location": "query", "method": "GET",
           "tests": {"baseline": {"status_code": 200, "body": "SECRET CONTENT" * 100,
                                  "sql_error_signature": False}}}
    red = redact_probe_data("sql_injection", raw)
    dumped = str(red)
    assert "SECRET CONTENT" not in dumped
    assert red["tests"]["baseline"]["length"] == len("SECRET CONTENT" * 100)
    assert red["tests"]["baseline"]["status_code"] == 200


def test_redaction_drops_body_key_for_other_probe_types():
    assert "body" not in redact_probe_data("xss", {"body": "x", "marker_reflected": True})
