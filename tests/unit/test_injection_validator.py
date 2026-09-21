"""
Independent validation of injection candidates: the validator must make its
OWN fresh probes (via the *.validate capability) and require repeatability
before confirming anything. A single HTTP 500/200/length delta is never
enough by itself.
"""

from __future__ import annotations

from core.models import Finding, FindingStatus, ToolResult
from validation.validator import FindingValidator

_LIST_BODY = "<ul class=\"results\"><li>Widget</li><li>Gadget</li><li>Gizmo</li></ul>"
BASE = {"status_code": 200, "body": _LIST_BODY, "sql_error_signature": False}
QUOTE_ERR = {"status_code": 500, "body": "you have an error in your sql syntax", "sql_error_signature": True}
QUOTE_OK = {"status_code": 200, "body": _LIST_BODY, "sql_error_signature": False}
TRUE_MATCH = {"status_code": 200, "body": _LIST_BODY, "sql_error_signature": False}
FALSE_EMPTY = {"status_code": 200, "body": "<ul class=\"results\"></ul>", "sql_error_signature": False}
FALSE_MATCH = dict(TRUE_MATCH)


def _sql_signal(url="http://h/search", parameter="q"):
    return {"validator": "sql_injection", "url": url, "parameter": parameter, "method": "GET", "location": "query"}


class FakeCtx:
    """Answers gateway-shaped calls with pre-scripted per-capability data, one item per call."""

    def __init__(self, scripted):
        self.scripted = dict(scripted)
        self.calls = []

    def lookup(self, query, purpose):
        return []

    async def call(self, capability, arguments, purpose=""):
        self.calls.append((capability, arguments))
        queue = self.scripted.get(capability)
        if queue is None:
            return ToolResult(status="tool_unavailable", error=f"no script for {capability}")
        item = queue.pop(0) if len(queue) > 1 else queue[0]
        if item is None:
            return ToolResult(status="error", error="simulated failure")
        return ToolResult(status="ok", data=item)


# ── SQL injection ─────────────────────────────────────────────────────────────

async def test_repeatable_error_based_sql_injection_is_confirmed():
    data = {"tests": {"baseline": BASE, "quote": QUOTE_ERR, "true": TRUE_MATCH, "false": FALSE_MATCH}}
    ctx = FakeCtx({"injection.sql.validate": [dict(data), dict(data)]})
    f = await FindingValidator(ctx).validate(Finding(signal=_sql_signal()))
    assert f.status == FindingStatus.CONFIRMED and f.confidence.value == "high"
    assert len(ctx.calls) == 2                                        # independent repeatability check


async def test_repeatable_boolean_based_sql_injection_is_confirmed():
    data = {"tests": {"baseline": BASE, "quote": QUOTE_OK, "true": TRUE_MATCH, "false": FALSE_EMPTY}}
    ctx = FakeCtx({"injection.sql.validate": [dict(data), dict(data)]})
    f = await FindingValidator(ctx).validate(Finding(signal=_sql_signal()))
    assert f.status == FindingStatus.CONFIRMED and f.confidence.value == "medium"


async def test_non_repeatable_sql_signal_is_inconclusive_not_confirmed():
    hit = {"tests": {"baseline": BASE, "quote": QUOTE_ERR, "true": TRUE_MATCH, "false": FALSE_MATCH}}
    miss = {"tests": {"baseline": BASE, "quote": QUOTE_OK, "true": TRUE_MATCH, "false": FALSE_MATCH}}
    ctx = FakeCtx({"injection.sql.validate": [hit, miss]})
    f = await FindingValidator(ctx).validate(Finding(signal=_sql_signal()))
    assert f.status == FindingStatus.INCONCLUSIVE


async def test_500_alone_without_error_signature_is_rejected_not_confirmed():
    """A generic 500 (framework error, unrelated crash) must never be treated as proof."""
    generic_500 = {"status_code": 500, "body": "Something went wrong.", "sql_error_signature": False}
    data = {"tests": {"baseline": BASE, "quote": generic_500, "true": TRUE_MATCH, "false": FALSE_MATCH}}
    ctx = FakeCtx({"injection.sql.validate": [dict(data), dict(data)]})
    f = await FindingValidator(ctx).validate(Finding(signal=_sql_signal()))
    assert f.status == FindingStatus.REJECTED


async def test_sql_validator_handles_tool_failure_as_inconclusive():
    ctx = FakeCtx({"injection.sql.validate": [None]})
    f = await FindingValidator(ctx).validate(Finding(signal=_sql_signal()))
    assert f.status == FindingStatus.INCONCLUSIVE


# ── XSS ───────────────────────────────────────────────────────────────────────

def _xss_signal():
    return {"validator": "reflected_xss", "url": "http://h/item", "parameter": "id", "method": "GET", "location": "query"}


async def test_unescaped_reflection_in_html_body_is_confirmed():
    ctx = FakeCtx({"injection.xss.validate": [{"marker_reflected": True, "escaped": False, "context": "html_body"}]})
    f = await FindingValidator(ctx).validate(Finding(signal=_xss_signal()))
    assert f.status == FindingStatus.CONFIRMED and f.confidence.value == "high"


async def test_escaped_reflection_is_rejected_as_false_positive():
    ctx = FakeCtx({"injection.xss.validate": [{"marker_reflected": True, "escaped": True, "context": "html_body"}]})
    f = await FindingValidator(ctx).validate(Finding(signal=_xss_signal()))
    assert f.status == FindingStatus.REJECTED


async def test_no_reflection_on_revalidation_is_rejected():
    ctx = FakeCtx({"injection.xss.validate": [{"marker_reflected": False, "escaped": False, "context": "absent"}]})
    f = await FindingValidator(ctx).validate(Finding(signal=_xss_signal()))
    assert f.status == FindingStatus.REJECTED


# ── SSRF ──────────────────────────────────────────────────────────────────────

def _ssrf_signal():
    return {"validator": "ssrf", "url": "http://h/fetch", "parameter": "url", "method": "GET", "location": "query"}


async def test_callback_received_confirms_ssrf():
    ctx = FakeCtx({"injection.ssrf.validate": [{"callback_received": True, "application_accepted": True}]})
    f = await FindingValidator(ctx).validate(Finding(signal=_ssrf_signal()))
    assert f.status == FindingStatus.CONFIRMED and f.confidence.value == "high"


async def test_accepted_but_no_callback_is_inconclusive_not_confirmed():
    ctx = FakeCtx({"injection.ssrf.validate": [{"callback_received": False, "application_accepted": True}]})
    f = await FindingValidator(ctx).validate(Finding(signal=_ssrf_signal()))
    assert f.status == FindingStatus.INCONCLUSIVE


async def test_rejected_url_and_no_callback_is_rejected():
    ctx = FakeCtx({"injection.ssrf.validate": [{"callback_received": False, "application_accepted": False}]})
    f = await FindingValidator(ctx).validate(Finding(signal=_ssrf_signal()))
    assert f.status == FindingStatus.REJECTED
