"""
core/runtime.py
---------------
Small, individually testable stages used by the adaptive loop.
"""

from __future__ import annotations

import logging
from typing import Any, Callable, Dict, List, Optional

from agents.base import AgentContext, AgentResult
from agents.registry import AgentRegistry
from core.models import (AgentActivity, Confidence, FindingStatus, TestTask, ToolRequest, ToolResult,
                         now_iso)
from core.state import AssessmentState
from intelligence.context import ContextManager
from recovery.controller import RecoveryController
from validation.outcome import conclude
from validation.validator import FindingValidator

logger = logging.getLogger("raven.runtime")
Emit = Callable[[str, str], None]

# statuses meaning "could not run", as opposed to "ran and failed"
_BLOCKING = {"out_of_scope", "tool_unavailable"}


class ValidationRuntime:
    """Gives the validator gateway access and knowledge lookup (ValidationContext)."""

    def __init__(self, recovery: RecoveryController, ctxmgr: ContextManager) -> None:
        self.recovery = recovery
        self.ctxmgr = ctxmgr

    async def call(self, capability: str, arguments: Dict[str, Any], purpose: str) -> ToolResult:
        return await self.recovery.execute(
            ToolRequest(capability=capability, arguments=arguments, purpose=purpose, agent="validator"))

    def lookup(self, query: str, purpose: str) -> List[str]:
        return self.ctxmgr.lookup(query, purpose)


async def execute_task(task: TestTask, state: AssessmentState, agents: AgentRegistry,
                       recovery: RecoveryController, ctxmgr: ContextManager) -> AgentResult:
    """Run one task with one agent. Never raises; always leaves the task in a final status."""
    agent = agents.get(task.agent)
    task.status, task.attempts = "running", task.attempts + 1
    activity = AgentActivity(agent=task.agent, task_id=task.task_id, title=task.title)
    state.agent_activity.append(activity)

    if agent is None:
        result = AgentResult(success=False, blocked=True, error=f"Agent '{task.agent}' is not registered.")
        ctx = None
    else:
        ctx = AgentContext(state, recovery, task, guidance=ctxmgr.agent_context(task))
        try:
            result = await agent.run(task, ctx)
        except Exception as e:  # agent bug: contain it, record it, continue the assessment
            logger.debug("Agent %s crashed", task.agent, exc_info=True)
            result = AgentResult(success=False, error=f"{type(e).__name__}: {e}")

    last = ctx.last_error if ctx else None
    if result.success:
        task.status = "done"
    elif result.blocked or (last is not None and last.status in _BLOCKING):
        task.status = "blocked"
    elif last is not None and last.status == "budget_exhausted":
        task.status = "skipped"
    else:
        task.status = "failed"
    task.result_summary = result.summary or result.error
    activity.finished_at, activity.outcome = now_iso(), task.status
    if task.status in ("failed", "blocked"):
        state.add_limitation(f"{task.title} {task.status}: {result.error or 'see tool failures'}")
    return result


async def validate_pending(state: AssessmentState, validator: FindingValidator,
                           can_continue: Callable[[], bool], emit: Optional[Emit] = None) -> int:
    """Validate every CANDIDATE finding. Anything left unvalidated becomes INCONCLUSIVE, never confirmed."""
    done = 0
    for f in list(state.candidate_findings):
        if not can_continue():
            break
        await validator.validate(f)
        done += 1
        if emit:
            emit("validated", f"{f.status.value.upper():12} {f.title[:70]}")
    return done


def close_unvalidated(state: AssessmentState) -> None:
    for f in state.candidate_findings:
        conclude(f, FindingStatus.INCONCLUSIVE, Confidence.LOW,
                 "Not validated (budget exhausted before validation); reported as unverified.", "none")
        state.add_limitation(f"Finding '{f.title[:60]}' could not be validated within budget.")
