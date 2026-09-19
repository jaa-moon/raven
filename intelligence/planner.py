"""
intelligence/planner.py
-----------------------
Decides *what to investigate next*. It is re-run every iteration of the
adaptive loop, so it always plans from the current TargetProfile, the tools
that exist, the budget that remains and what has already been tried.

Deterministic core: agents propose tasks; the planner de-duplicates, checks
capability availability, applies budget policy and ranks. The optional LLM
may only nudge priorities (bounded, never touching discovery-critical work);
it cannot invent tasks, tools, or override scope/budget.
"""

from __future__ import annotations

import logging
from typing import Dict, List, Optional

from agents.registry import AgentRegistry
from core.budget import BudgetManager
from core.models import TestPlan, TestTask
from core.state import AssessmentState
from intelligence.context import ContextManager
from intelligence.llm import LLM
from raven_mcp.gateway import Gateway

logger = logging.getLogger("raven.planner")

# minimum priority still worth running at each budget status
BUDGET_FLOOR = {"ok": 0, "constrained": 60, "critical": 85, "exhausted": 101}
LLM_MAX_DELTA = 15
LLM_IMMUNE_PRIORITY = 95


class Planner:
    def __init__(self, agents: AgentRegistry, gateway: Gateway, budget: BudgetManager,
                 ctx: ContextManager, llm: Optional[LLM] = None) -> None:
        self.agents = agents
        self.gateway = gateway
        self.budget = budget
        self.ctx = ctx
        self.llm = llm or LLM(None)

    # -- planning -----------------------------------------------------------------

    async def replan(self, state: AssessmentState, reason: str = "") -> List[TestTask]:
        """Add newly-justified tasks to the state. Returns the tasks that were added."""
        rag = self.ctx.for_planning()
        known = state.task_keys()
        proposals: List[TestTask] = []
        for agent in self.agents.applicable(state.profile):
            for t in agent.propose_tasks(state):
                if t.key not in known and all(t.key != p.key for p in proposals):
                    proposals.append(t)

        added: List[TestTask] = []
        floor = BUDGET_FLOOR[self.budget.status()]
        for t in proposals:
            if not self.gateway.can_provide(t.capability):
                t.status = "blocked"
                t.result_summary = self.gateway.registry.missing_capability_reason(t.capability)
                state.add_limitation(f"{t.title}: {t.result_summary}")
            elif t.priority < floor or (t.cost > self._affordable_calls() and t.priority < 95):
                t.status = "skipped"
                t.result_summary = f"skipped: budget {self.budget.status()}"
                state.add_limitation(f"'{t.title}' skipped to conserve budget ({self.budget.status()}).")
            added.append(t)

        pending = [t for t in added if t.status == "pending"]
        if len(pending) >= 2:
            await self._llm_prioritize(state, pending, rag)

        state.tasks.extend(added)
        state.plan = TestPlan(
            version=state.plan.version + 1 if state.tasks and state.plan.task_ids else 1,
            generated_by="llm" if self.llm.available and len(pending) >= 2 else "deterministic",
            rationale=reason or "Initial plan from target profile.",
            task_ids=[t.task_id for t in state.tasks if t.status == "pending"])
        if added:
            state.add_note(f"Plan v{state.plan.version} ({reason or 'initial'}): +{len(added)} task(s) "
                           f"[{', '.join(t.key for t in added if t.status == 'pending')[:200]}]")
        return added

    def _affordable_calls(self) -> int:
        return max(self.budget.limits.max_tool_calls - self.budget.tool_calls, 0)

    def apply_budget_policy(self, state: AssessmentState) -> List[TestTask]:
        """As the budget shrinks, drop queued lower-priority work *now* (recorded), keeping
        headroom for validation, instead of running until the budget is gone."""
        floor = BUDGET_FLOOR[self.budget.status()]
        dropped = []
        for t in state.tasks:
            if t.status == "pending" and t.priority < floor:
                t.status = "skipped"
                t.result_summary = f"skipped: budget {self.budget.status()}"
                dropped.append(t)
        if dropped:
            state.add_limitation(f"{len(dropped)} lower-priority test(s) skipped to conserve budget "
                                 f"({self.budget.status()}): {', '.join(t.title for t in dropped[:4])}"
                                 f"{'...' if len(dropped) > 4 else ''}")
        return dropped

    def next_task(self, state: AssessmentState) -> Optional[TestTask]:
        self.apply_budget_policy(state)
        pending = [(i, t) for i, t in enumerate(state.tasks) if t.status == "pending"]
        if not pending:
            return None
        return max(pending, key=lambda it: (it[1].priority, -it[1].cost, -it[0]))[1]

    # -- optional LLM prioritization -----------------------------------------------

    async def _llm_prioritize(self, state: AssessmentState, tasks: List[TestTask], rag) -> None:
        if not self.llm.available:
            return
        p = state.profile
        listing = [{"id": t.task_id, "title": t.title, "priority": t.priority, "why": t.rationale}
                   for t in tasks]
        guidance = [{"title": s.title, "text": s.text[:300]} for s in rag.snippets]
        data = await self.llm.ask_json(
            "You prioritize security-assessment tasks. You may only adjust priorities.",
            f"Target: {p.target_type}; technologies: {p.technologies}; surfaces: {p.surfaces}; "
            f"budget: {self.budget.status()}\nGuidance: {guidance}\nTasks: {listing}\n"
            f'Return {{"adjust": [{{"id": "<task id>", "delta": <int -{LLM_MAX_DELTA}..{LLM_MAX_DELTA}>, '
            f'"reason": "<short>"}}]}}')
        by_id: Dict[str, TestTask] = {t.task_id: t for t in tasks}
        for adj in (data or {}).get("adjust", [])[:20]:
            t = by_id.get(str(adj.get("id")))
            try:
                delta = int(adj.get("delta", 0))
            except (TypeError, ValueError):
                continue
            if t is None or t.priority >= LLM_IMMUNE_PRIORITY:
                continue
            t.priority = max(0, min(94, t.priority + max(-LLM_MAX_DELTA, min(LLM_MAX_DELTA, delta))))
            t.rationale = f"{t.rationale} [LLM: {str(adj.get('reason', ''))[:80]}]".strip()
