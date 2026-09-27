"""agents/web_exposure.py: partial path-group failures must not be silently dropped."""

from __future__ import annotations

import pytest

from agents.base import AgentContext
from agents.web_exposure import GROUPS, WebExposureAgent
from core.models import TestTask, ToolResult
from core.profile import TargetProfile
from core.state import AssessmentState

FAIL_PATHS = {"/actuator/env", "/debug"}   # 2 of the 6 "debug" group paths


def _make_ctx():
    state = AssessmentState()
    state.profile = TargetProfile(target_type="web_application",
                                  attributes={"base_url": "http://fixture.test"})
    task = TestTask(key="web_exposure.paths::debug", agent="web_exposure", capability="http_request",
                    surface="Exposed paths & files", title="Exposed paths & files",
                    params={"paths": list(GROUPS["debug"])})
    ctx = AgentContext(state, recovery=None, task=task)

    async def fake_call(capability, arguments, purpose=""):
        assert capability == "http_request"
        path = arguments["url"].split("http://fixture.test", 1)[1]
        if path in FAIL_PATHS:
            return ToolResult(status="error", error="simulated connection reset")
        return ToolResult(status="ok", data={"status_code": 404, "headers": {}, "body": "Not Found"})

    ctx.call = fake_call
    return ctx, task, state


async def test_two_of_six_path_failures_are_tolerated_but_recorded_as_a_limitation():
    ctx, task, state = _make_ctx()
    result = await WebExposureAgent().run(task, ctx)

    assert result.success is True                         # tolerated: 2 < 3-failure hard-fail threshold
    assert "could not be fetched" in result.summary
    limitation = next((l for l in state.limitations if "could not be fetched" in l), None)
    assert limitation is not None
    assert "2 of 6" in limitation
    assert "/actuator/env" in limitation and "/debug" in limitation   # names the specific failed paths

    fetch_failed = [o for o in state.observations if o.kind == "path.fetch_failed"]
    assert {o.data["path"] for o in fetch_failed} == FAIL_PATHS


async def test_three_failures_still_hard_fails_the_task_unchanged():
    ctx, task, state = _make_ctx()

    async def fake_call_three_fail(capability, arguments, purpose=""):
        path = arguments["url"].split("http://fixture.test", 1)[1]
        if path in ("/actuator", "/actuator/env", "/actuator/health"):
            return ToolResult(status="error", error="simulated connection reset")
        return ToolResult(status="ok", data={"status_code": 404, "headers": {}, "body": "Not Found"})

    ctx.call = fake_call_three_fail
    result = await WebExposureAgent().run(task, ctx)
    assert result.success is False and result.error == "simulated connection reset"
