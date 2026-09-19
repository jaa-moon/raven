"""MCP gateway (validation, scope, budget, failures) and the recovery controller."""

import asyncio

from core.budget import BudgetLimits, BudgetManager
from core.models import ToolRequest
from core.scope import Scope, ScopeValidator
from core.state import AssessmentState
from raven_mcp.gateway import Gateway
from raven_mcp.models import ParamSpec, ToolDefinition, ToolError
from raven_mcp.registry import ToolRegistry
from recovery.controller import RecoveryController


def _tool(name, handler, caps=None, **kw):
    return ToolDefinition(name=name, capabilities=caps or [name], handler=handler, **kw)


async def _echo(url, n=1):
    return {"url": url, "n": n}


def _gateway(*tools, limits=None, scope=None):
    reg = ToolRegistry()
    for t in tools:
        reg.register(t)
    scope = scope or Scope(allowed_hosts=["localhost"], max_risk="low")
    budget = BudgetManager(limits or BudgetLimits(max_tool_calls=50))
    return Gateway(reg, ScopeValidator(scope), budget), budget


ECHO = dict(input_schema={"url": ParamSpec(required=True), "n": ParamSpec(type="int", default=1)},
            scope_args={"url": "url"})


async def test_valid_request_is_executed_and_normalized():
    gw, budget = _gateway(_tool("echo", _echo, ["http_request"], **ECHO))
    r = await gw.execute(ToolRequest(capability="http_request", arguments={"url": "http://localhost/x", "n": "3"}))
    assert r.ok and r.data == {"url": "http://localhost/x", "n": 3}
    assert budget.tool_calls == 1 and len(gw.calls) == 1


async def test_invalid_arguments_are_rejected_before_execution():
    gw, budget = _gateway(_tool("echo", _echo, ["http_request"], **ECHO))
    r = await gw.execute(ToolRequest(capability="http_request", arguments={"n": 1, "bogus": 2}))
    assert r.status == "invalid_args" and "url" in r.error and "bogus" in r.error
    assert budget.tool_calls == 0


async def test_scope_violation_never_reaches_the_tool():
    called = []

    async def spy(url):
        called.append(url)
        return {}

    gw, _ = _gateway(_tool("spy", spy, ["c"], input_schema={"url": ParamSpec(required=True)}, scope_args={"url": "url"}))
    r = await gw.execute(ToolRequest(capability="c", arguments={"url": "http://evil.example/"}))
    assert r.status == "out_of_scope" and called == []


async def test_high_risk_tool_is_blocked_by_scope_risk_cap():
    gw, _ = _gateway(_tool("dangerous", lambda: {}, risk_level="high"))
    assert (await gw.execute(ToolRequest(capability="dangerous"))).status == "out_of_scope"


async def test_budget_exhaustion_blocks_execution():
    gw, budget = _gateway(_tool("t", lambda: {"ok": 1}), limits=BudgetLimits(max_tool_calls=2))
    assert (await gw.execute(ToolRequest(capability="t"))).ok
    assert (await gw.execute(ToolRequest(capability="t"))).ok
    r = await gw.execute(ToolRequest(capability="t"))
    assert r.status == "budget_exhausted" and budget.tool_calls == 2


async def test_tool_crash_timeout_and_classified_errors_are_contained():
    async def boom():
        raise RuntimeError("kaput")

    async def slow():
        await asyncio.sleep(2)

    async def down():
        raise ToolError("target_unreachable", "refused")

    gw, _ = _gateway(_tool("boom", boom), _tool("slow", slow, timeout_seconds=0.05), _tool("down", down))
    assert (await gw.execute(ToolRequest(capability="boom"))).status == "error"
    assert (await gw.execute(ToolRequest(capability="slow"))).status == "timeout"
    assert (await gw.execute(ToolRequest(capability="down"))).status == "target_unreachable"


async def test_capability_resolution_and_unavailable_tools():
    gw, _ = _gateway(_tool("needs", lambda: {}, requirements=["bin:no-such-binary-xyz"]))
    r = await gw.execute(ToolRequest(capability="needs"))
    assert r.status == "tool_unavailable" and "no-such-binary-xyz" in r.error
    assert (await gw.execute(ToolRequest(capability="nothing"))).status == "tool_unavailable"


# ── recovery ──────────────────────────────────────────────────────────────────

def _recovery(gw, budget, sleeps):
    async def fake_sleep(d):
        sleeps.append(d)
    return RecoveryController(gw, budget, AssessmentState(), sleep=fake_sleep)


async def test_unreachable_target_is_retried_with_backoff_then_succeeds():
    n = {"calls": 0}

    async def flaky():
        n["calls"] += 1
        if n["calls"] < 3:
            raise ToolError("target_unreachable", "refused")
        return {"ok": True}

    gw, budget = _gateway(_tool("flaky", flaky), limits=BudgetLimits(max_tool_calls=20, max_retries=3))
    sleeps: list = []
    rc = _recovery(gw, budget, sleeps)
    assert (await rc.execute(ToolRequest(capability="flaky"))).ok
    assert sleeps == [0.5, 1.0]
    assert [r.action for r in rc.state.recovery_actions] == ["retry_backoff", "retry_backoff"]


async def test_crashing_tool_falls_back_to_an_alternative_provider():
    async def bad():
        raise RuntimeError("a is broken")

    gw, budget = _gateway(_tool("a", bad, ["x"]), _tool("b", lambda: {"from": "b"}, ["x"], risk_level="low"))
    rc = _recovery(gw, budget, [])
    r = await rc.execute(ToolRequest(capability="x"))
    assert r.ok and r.data == {"from": "b"}
    assert "alternative_tool" in [a.action for a in rc.state.recovery_actions]


async def test_scope_and_budget_failures_are_not_retried_and_are_recorded():
    gw, budget = _gateway(_tool("dangerous", lambda: {}, risk_level="high"))
    rc = _recovery(gw, budget, [])
    r = await rc.execute(ToolRequest(capability="dangerous"))
    assert r.status == "out_of_scope"
    assert [a.action for a in rc.state.recovery_actions] == ["block"]
    assert budget.tool_calls == 0


async def test_unknown_arguments_are_corrected_once():
    gw, budget = _gateway(_tool("echo", _echo, ["http_request"], **ECHO))
    rc = _recovery(gw, budget, [])
    r = await rc.execute(ToolRequest(capability="http_request", arguments={"url": "http://localhost/", "junk": 1}))
    assert r.ok and "correct_args" in [a.action for a in rc.state.recovery_actions]


async def test_persistent_timeout_is_skipped_not_fatal():
    async def slow():
        await asyncio.sleep(2)

    gw, budget = _gateway(_tool("slow", slow, timeout_seconds=0.02), limits=BudgetLimits(max_tool_calls=20))
    rc = _recovery(gw, budget, [])
    r = await rc.execute(ToolRequest(capability="slow"))
    assert r.status == "timeout" and "[recovery: skip]" in r.error
