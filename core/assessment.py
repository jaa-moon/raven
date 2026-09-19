"""
core/assessment.py
------------------
The adaptive assessment loop:

    observe -> understand -> plan -> act -> observe -> update context -> re-plan

Each stage is a small function in core.runtime / the planner / the validator;
this module only sequences them.
"""

from __future__ import annotations

import asyncio
import logging
from pathlib import Path
from typing import Callable, Dict, Iterable, Optional

from agents.registry import AgentRegistry, default_registry
from core.budget import BudgetLimits, BudgetManager
from core.coverage import compute_coverage, overall_state
from core.runtime import ValidationRuntime, close_unvalidated, execute_task, validate_pending
from core.scope import Scope, ScopeValidator
from core.state import AssessmentState
from core.target import check_reachability, parse_target
from intelligence.context import ContextManager
from intelligence.lessons import learn
from intelligence.llm import LLM
from intelligence.planner import Planner
from intelligence.rag import KnowledgeBase
from intelligence.target_analyzer import TargetAnalyzer
from raven_mcp.gateway import Gateway
from raven_mcp.registry import ToolRegistry
from recovery.controller import RecoveryController
from tools.catalog import build_registry
from validation.validator import FindingValidator

logger = logging.getLogger("raven.assessment")
Emit = Callable[[str, str], None]


async def run_assessment(
    raw_target: Optional[str] = None,
    *,
    resume_id: Optional[str] = None,
    depth: str = "standard",
    max_risk: str = "low",
    extra_hosts: Iterable[str] = (),
    llm_config: Optional[Dict] = None,
    tools: Optional[ToolRegistry] = None,
    agents: Optional[AgentRegistry] = None,
    kb: Optional[KnowledgeBase] = None,
    state_root: Optional[Path] = None,
    limits: Optional[BudgetLimits] = None,
    learn_lessons: bool = True,
    authorized: bool = False,
    check_reach: bool = True,
    emit: Optional[Emit] = None,
    sleep: Callable = asyncio.sleep,
) -> AssessmentState:
    say: Emit = emit or (lambda kind, msg: None)
    if not authorized:
        raise PermissionError("Explicit operator authorization is required (authorized=True).")

    # -- 1. intake (or resume) ------------------------------------------------------
    resumed = resume_id is not None
    if resumed:
        state = AssessmentState.load(resume_id, state_root)
        target = state.target
        reachable = state.profile.reachable
        _prepare_resume(state)
        say("intake", f"resuming {state.assessment_id}: {len(state.completed_tasks)} task(s) already done")
    else:
        if not raw_target:
            raise ValueError("A target (or resume_id) is required.")
        target = parse_target(raw_target)
        state = AssessmentState(target=target)
        reachable = await asyncio.to_thread(check_reachability, target) if check_reach else True
        state.scope = Scope.from_target(target, max_risk=max_risk).extended(hosts=extra_hosts)
        say("intake", f"{target.input_type.value}: {target.normalized_target} (reachable={reachable})")
    budget = BudgetManager(limits or BudgetLimits.for_depth(depth))
    if resumed:
        _restore_budget(budget, state.budget)

    # -- 2. wiring ------------------------------------------------------------------
    registry = tools or build_registry()
    gateway = Gateway(registry, ScopeValidator(state.scope), budget, on_call=state.tool_calls.append)
    recovery = RecoveryController(gateway, budget, state, sleep=sleep)
    llm = LLM.from_config(llm_config, budget)
    knowledge = kb or KnowledgeBase()
    ctxmgr = ContextManager(knowledge, state)
    agent_registry = agents or default_registry()
    planner = Planner(agent_registry, gateway, budget, ctxmgr, llm)
    validator = FindingValidator(ValidationRuntime(recovery, ctxmgr))
    say("llm", llm.describe())

    # -- 3. target analysis -> TargetProfile ---------------------------------------------
    state.phase = "analysis"
    if not resumed:
        await TargetAnalyzer(state, recovery, llm).analyze(reachable_hint=reachable)
    gateway.target_type = state.profile.target_type
    state.profile.attributes["capabilities_available"] = sorted(registry.capabilities())
    p = state.profile
    say("profile", f"{p.target_type}; surfaces={p.surfaces}; technologies={p.technologies}; reachable={p.reachable}")

    # -- 4. adaptive loop ----------------------------------------------------------------
    state.phase = "assessment"
    if not p.reachable and p.target_type not in ("source_repository", "file", "binary"):
        state.add_limitation("Target was unreachable; no assessment tasks were executed.")
    else:
        await planner.replan(state, "resumed assessment" if resumed else "initial plan from target profile")
        signature = p.signature()
        while budget.loop_may_continue():
            task = planner.next_task(state)
            if task is None:
                break
            budget.next_iteration()
            say("task", f"{task.agent}: {task.title}")
            await execute_task(task, state, agent_registry, recovery, ctxmgr)
            say("task-result", f"{task.status}: {task.result_summary[:100]}")
            await validate_pending(state, validator, budget.can_afford, say)
            if p.signature() != signature:               # new knowledge -> re-plan
                signature = p.signature()
                added = await planner.replan(state, f"new knowledge after '{task.title}'")
                say("replan", f"+{len(added)} task(s)")
            state.budget = budget.snapshot()
            state.save(state_root)

    # -- 5. wrap-up ------------------------------------------------------------------------
    state.phase = "validation"
    await validate_pending(state, validator, budget.can_afford, say)
    close_unvalidated(state)
    for t in state.pending_tasks:
        t.status = "skipped"
        t.result_summary = f"not run: budget {budget.status()} / iteration limit"
    if state.pending_tasks or any(t.result_summary.startswith("not run") for t in state.tasks):
        state.add_limitation("Assessment stopped early; remaining lower-priority tests were not run "
                             f"(budget: {', '.join(budget.exhausted_dimensions()) or budget.status()}).")
    state.phase = "reporting"
    state.coverage = compute_coverage(p.target_type, state.tasks)
    state.overall_state = overall_state(state.coverage)
    state.budget = budget.snapshot()
    if learn_lessons:
        stored = learn(state, knowledge)
        if stored:
            say("learning", f"stored {len(stored)} validated lesson(s)")
    state.phase = "complete"
    from core.models import now_iso
    state.finished_at = now_iso()
    state.save(state_root)
    return state


def _prepare_resume(state: AssessmentState) -> None:
    """Make an interrupted/finished-early state runnable again."""
    for t in state.tasks:
        interrupted = t.status == "running"
        deferred = t.status == "skipped" and (t.result_summary.startswith("not run")
                                              or t.result_summary.startswith("skipped: budget"))
        if interrupted or deferred:
            t.status, t.result_summary = "pending", ""
    state.limitations = [l for l in state.limitations
                         if not l.startswith("Assessment stopped early") and "conserve budget" not in l]
    state.add_note("Assessment resumed from saved state.")


def _restore_budget(budget: BudgetManager, snap: Dict) -> None:
    """Carry consumption forward so a resumed run is bounded by the *same* limits."""
    if not snap:
        return
    budget.tool_calls = int(snap.get("tool_calls", 0))
    budget.llm_calls = int(snap.get("llm_calls", 0))
    budget.expensive_ops = int(snap.get("expensive_ops", 0))
    budget.iterations = int(snap.get("iterations", 0))
    budget._start -= float(snap.get("elapsed_seconds", 0.0))
