"""
recovery/controller.py
----------------------
Failures are normal in an autonomous assessment. Every failed tool call is
classified and answered with an explicit, *recorded* decision; a single
failure never ends the assessment.
"""

from __future__ import annotations

import asyncio
import re
from enum import Enum
from typing import Awaitable, Callable

from pydantic import BaseModel

from core.budget import BudgetManager
from core.models import RecoveryRecord, ToolRequest, ToolResult
from core.state import AssessmentState
from raven_mcp.gateway import Gateway


class RecoveryAction(str, Enum):
    NONE = "none"
    RETRY = "retry"
    RETRY_BACKOFF = "retry_backoff"
    ALTERNATIVE_TOOL = "alternative_tool"
    CORRECT_ARGS = "correct_args"
    SKIP = "skip"
    BLOCK = "block"
    ABORT = "abort"


class RecoveryDecision(BaseModel):
    action: RecoveryAction
    delay: float = 0.0
    detail: str = ""


Sleep = Callable[[float], Awaitable[None]]


class RecoveryController:
    def __init__(self, gateway: Gateway, budget: BudgetManager, state: AssessmentState,
                 sleep: Sleep = asyncio.sleep, base_delay: float = 0.5) -> None:
        self.gateway = gateway
        self.budget = budget
        self.state = state
        self._sleep = sleep
        self._base = base_delay

    # -- policy ---------------------------------------------------------------------

    def decide(self, req: ToolRequest, res: ToolResult, attempt: int) -> RecoveryDecision:
        s = res.status
        key = f"{req.capability}:{sorted(req.arguments.items())[:2]}"
        retry_ok = lambda: self.budget.record_retry(key)  # noqa: E731

        if s == "out_of_scope":
            return RecoveryDecision(action=RecoveryAction.BLOCK, detail=f"Blocked by scope: {res.error}")
        if s == "budget_exhausted":
            return RecoveryDecision(action=RecoveryAction.ABORT, detail="Budget exhausted; stopping lower-priority work.")
        if s == "tool_unavailable":
            return RecoveryDecision(action=RecoveryAction.BLOCK, detail=f"Capability unavailable: {res.error}")
        if s == "auth_failure":
            return RecoveryDecision(action=RecoveryAction.SKIP,
                                    detail="Authentication required; recorded as a limitation.")
        if s == "invalid_args":
            unknown = re.search(r"unknown argument\(s\): ([\w, ]+)", res.error)
            if unknown and attempt == 0:
                return RecoveryDecision(action=RecoveryAction.CORRECT_ARGS,
                                        detail=f"Dropping unknown arguments: {unknown.group(1)}")
            return RecoveryDecision(action=RecoveryAction.SKIP, detail=f"Invalid arguments: {res.error}")
        if s == "timeout":
            if attempt == 0 and retry_ok():
                return RecoveryDecision(action=RecoveryAction.RETRY, detail="Timeout; retrying once.")
            return self._alternative_or_skip(req, res, "Repeated timeout")
        if s in ("target_unreachable", "rate_limited"):
            if retry_ok():
                delay = self._base * (2 ** attempt) * (4 if s == "rate_limited" else 1)
                return RecoveryDecision(action=RecoveryAction.RETRY_BACKOFF, delay=min(delay, 30.0),
                                        detail=f"{s}; backing off {min(delay, 30.0):.1f}s.")
            return RecoveryDecision(action=RecoveryAction.SKIP, detail=f"{s} persisted after retries.")
        # generic tool crash / error
        if attempt == 0 and retry_ok():
            return RecoveryDecision(action=RecoveryAction.RETRY, detail="Tool error; retrying once.")
        return self._alternative_or_skip(req, res, "Tool keeps failing")

    def _alternative_or_skip(self, req: ToolRequest, res: ToolResult, why: str) -> RecoveryDecision:
        alts = self.gateway.alternatives(req.capability, req.exclude_tools + [res.tool])
        if alts:
            return RecoveryDecision(action=RecoveryAction.ALTERNATIVE_TOOL, detail=f"{why}; switching to '{alts[0]}'.")
        return RecoveryDecision(action=RecoveryAction.SKIP, detail=f"{why}; no alternative tool provides this capability.")

    # -- execution ------------------------------------------------------------------

    async def execute(self, req: ToolRequest) -> ToolResult:
        attempt = 0
        while True:
            res = await self.gateway.execute(req)
            if res.ok:
                return res
            d = self.decide(req, res, attempt)
            self.state.recovery_actions.append(RecoveryRecord(
                request_id=req.request_id, capability=req.capability, tool=res.tool,
                failure_type=res.status, action=d.action.value, detail=d.detail))
            if d.action in (RecoveryAction.RETRY, RecoveryAction.RETRY_BACKOFF):
                if d.delay:
                    await self._sleep(d.delay)
            elif d.action == RecoveryAction.ALTERNATIVE_TOOL:
                req = req.model_copy(update={"exclude_tools": req.exclude_tools + [res.tool]})
            elif d.action == RecoveryAction.CORRECT_ARGS:
                bad = set(re.findall(r"\w+", d.detail.split(":", 1)[1]))
                req = req.model_copy(update={"arguments": {k: v for k, v in req.arguments.items() if k not in bad}})
            else:
                res.error = f"{res.error} [recovery: {d.action.value}]"
                return res
            attempt += 1
            if attempt > 6:  # hard stop; policies above already bound this
                return res
